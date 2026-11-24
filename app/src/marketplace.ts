// Marketplace mode on a real escrow: one shielded 2-of-3 FROST escrow per deal, paid out in
// stages (deal.ts), each stage a transaction that pays its outputs and returns the rest to the
// escrow group's own internal address.
//
// Share holders (makeEscrowGroup with operator, policy, arbiter):
//   operator  the marketplace (CrowdStore). Proposes stages and signs events and instructions.
//   policy    a policy co-signer: signs only instructions that its own replica of the deal state
//             machine allows, each stage id once. It holds no other authority.
//   arbiter   an independent arbiter: resolves disputes with a signed event and can stand in for
//             the operator or the policy co-signer. Predge can be the arbiter but does not have to be.
// Any two sign; no one moves funds alone. Ordinary stages: operator + policy.
//
// Every signer re-derives the stage from the signed event log (checkStage) and releases its FROST
// share only through `zescrow-frost sign-pczt` with the stage's exact payments and exact change
// to the group (`--change-to-group`).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkPayout, type Expect } from "./payout-check.ts";
import {
  DEFAULT_NETWORK_FEE_BUDGET_ZAT, DEFAULT_SPLIT, DEAL_SCHEMA, applyEvent, applyStage, checkStage, fundingZat, newDeal, planStage,
  replay, signEvent, signStage,
  type DealEvent, type DealState, type DealTerms, type RecipientBinding, type SignedEvent, type SignedStage, type StageKind,
} from "./deal.ts";
import {
  STATE, ageFile, balance, ensureBuyerFunds, ensureWallet, fmt, frostSign, jobDir, makeEscrowGroup, minedHeight, partyAddress,
  partyDir, waitChain, waitIndexer, walletDir, zip321Uri, type Party,
} from "./escrow.ts";
import { localQuoteSigner, type SignedQuote } from "./pricelock.ts";
import { LIGHTWALLETD, NETWORK, TESTNET, devtool, mine, say } from "./tools.ts";
import { canonical, loadArbiterKey, sha256 } from "./verdict.ts";

interface StageRecord {
  after_event: number;
  stage: SignedStage;
  txid: string;
  height?: number;
  topup_txid?: string;
}

export interface MarketDeal {
  id: string;
  terms: DealTerms;
  events: SignedEvent[];
  stages: StageRecord[];
  fund_txid?: string;
  fund_height?: number;
  /** The quote the deposit was computed from, and when the buyer sent it (saved before sending). */
  funding?: { quote: SignedQuote; paid_at: string };
}

const dealFile = (id: string) => join(jobDir(id), "deal.json");
export const loadDeal = (id: string): MarketDeal => JSON.parse(readFileSync(dealFile(id), "utf8")) as MarketDeal;
const saveDeal = (d: MarketDeal) => {
  mkdirSync(jobDir(d.id), { recursive: true });
  writeFileSync(dealFile(d.id), JSON.stringify(d, null, 2));
};

const operatorKey = () => loadArbiterKey(join(partyDir("operator"), "operator-ed25519.pem"));
const arbiterKey = () => loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));
export const quoteSigner = () => localQuoteSigner(join(STATE, "quote-signer", "quote-ed25519.pem"));

/** The deal state as every party computes it: the terms, the signed events and the executed stages, all re-verified. */
export function dealState(d: MarketDeal): DealState {
  return replay(d.terms, d.events, d.stages.map((r) => ({ after_event: r.after_event, stage: r.stage })));
}

// ---------- one-shot stage ledger, per signer ----------

const ledgerFile = (p: Party) => join(partyDir(p), "stage-ledger.json");
export function signedStages(p: Party): string[] {
  return existsSync(ledgerFile(p)) ? (JSON.parse(readFileSync(ledgerFile(p), "utf8")) as string[]) : [];
}
function recordSigned(p: Party, stageId: string) {
  const l = signedStages(p);
  if (l.includes(stageId)) return; // one share per spend of the same stage
  mkdirSync(partyDir(p), { recursive: true });
  writeFileSync(ledgerFile(p), JSON.stringify([...l, stageId], null, 2));
}

// ---------- deal lifecycle ----------

export function createDeal(id: string, amountUsdCents: number): MarketDeal {
  say(`== deal ${id}: marketplace escrow for $${(amountUsdCents / 100).toFixed(2)} (fiat terms, split ${DEFAULT_SPLIT.seller_bps}/${DEFAULT_SPLIT.reward_bps}/${DEFAULT_SPLIT.fee_bps} bps)`);
  const feeAddress = ensureWallet("marketplace");
  const reserveAddress = ensureWallet("reserve");
  const g = makeEscrowGroup(id, ["operator", "policy", "arbiter"]);
  const terms: DealTerms = {
    schema: DEAL_SCHEMA, deal_id: id, amount_usd_cents: amountUsdCents, split: DEFAULT_SPLIT,
    fee_address: feeAddress, reserve_address: reserveAddress,
    escrow_address: g.address, escrow_ufvk: g.ufvk, group_ak: g.ak,
    operator_pubkey: operatorKey().pubHex, arbiter_pubkey: arbiterKey().pubHex, quote_pubkey: quoteSigner().pubHex,
    quote_max_age_s: 900, price_tolerance_bps: 100, network_fee_budget_zat: DEFAULT_NETWORK_FEE_BUDGET_ZAT,
  };
  newDeal(terms);
  const d: MarketDeal = { id, terms, events: [], stages: [] };
  saveDeal(d);
  say(`  escrow ${g.address.slice(0, 32)}…, FROST 2-of-3: operator, policy co-signer, arbiter (group key ${g.ak.slice(0, 16)}…)`);
  return d;
}

function appendEvent(d: MarketDeal, event: DealEvent, issuer: "operator" | "arbiter"): DealState {
  const st = dealState(d);
  const se = signEvent(st, event, issuer, issuer === "operator" ? operatorKey() : arbiterKey());
  const next = applyEvent(st, se);
  d.events.push(se);
  saveDeal(d);
  say(`  event ${se.envelope.seq}: ${event.type}${"sentiment" in event ? ` (${event.sentiment})` : ""} signed by the ${issuer}; shares ${JSON.stringify(next.shares)}`);
  return next;
}

export const operatorEvent = (id: string, e: DealEvent) => appendEvent(loadDeal(id), e, "operator");
export const arbiterEvent = (id: string, e: DealEvent) => appendEvent(loadDeal(id), e, "arbiter");

/**
 * The buyer funds the fiat amount at the funding quote, plus the network fee budget. Resumable:
 * the quote and payment time are saved before the send, and a deposit the escrow wallet already
 * sees is not sent again.
 */
export async function fundDeal(id: string, quote: SignedQuote): Promise<MarketDeal> {
  const d = loadDeal(id);
  const ew = join(jobDir(id), "wallet");
  if (dealState(d).status !== "created") return d; // resumed after funding
  if (d.funding) quote = d.funding.quote;
  const need = fundingZat(d.terms, quote);
  say(`== deal ${id}: buyer funds ${fmt(need)} ($${(d.terms.amount_usd_cents / 100).toFixed(2)} at $${(quote.quote.price_micros / 1e6).toFixed(2)}/ZEC + ${d.terms.network_fee_budget_zat} zat network fee budget)`);
  if (!d.fund_txid && balance(ew).total === 0) {
    await ensureBuyerFunds(need + 20_000);
    d.funding = { quote, paid_at: new Date().toISOString() };
    saveDeal(d);
    const termsHash = sha256(canonical(d.terms));
    const out = devtool(["wallet", "-w", walletDir("buyer"), "send", "-i", ageFile("buyer"), "--address", d.terms.escrow_address,
      "--value", String(need), "--memo", `zescrow fund ${id} terms ${termsHash.slice(0, 16)}`, "-s", LIGHTWALLETD]);
    d.fund_txid = out.trim().split("\n").pop();
    saveDeal(d);
  } else {
    say("  deposit already sent; resuming");
  }
  if (TESTNET) {
    say(`  fund tx ${d.fund_txid}`);
    await waitChain("the deposit to confirm in the escrow wallet", () => { const b = balance(ew); return { ok: b.ironwood >= need, tip: b.tip }; }, 120);
    d.fund_height = minedHeight(ew, d.fund_txid!);
  } else {
    await mine(10);
    await waitIndexer();
  }
  const b = balance(ew);
  saveDeal(d);
  if (!d.fund_txid) d.fund_txid = (JSON.parse(devtool(["wallet", "-w", ew, "list-tx", "--json"], { quiet: true }).trim().split("\n").pop()!) as { txid: string }[])[0]?.txid;
  if (!d.fund_height && d.fund_txid) d.fund_height = minedHeight(ew, d.fund_txid);
  saveDeal(d);
  appendEvent(d, { type: "funded", funded_zat: b.ironwood, quote, paid_at: d.funding!.paid_at, fund_txid: d.fund_txid }, "operator");
  say(`  escrow holds ${fmt(b.ironwood)} (tx ${d.fund_txid?.slice(0, 16)}…)`);
  return d;
}

/** The operator's attestation of a payout address it got from the party's account. */
export function bindAddress(party: RecipientBinding["party"], address: string): RecipientBinding {
  return { party, address, attested_by: "operator", source: "crowdstore account (testnet demo: party wallet)" };
}

/** Each signer's own check of a stage: its replica of the state, its ledger; returns its PCZT policy. */
function signerExpect(d: MarketDeal, ss: SignedStage, p: Party, reference?: number): Expect {
  const e = checkStage(dealState(d), ss, { signed: signedStages(p), reference_price_micros: reference });
  return { to: e.to, min: e.min, max: e.max, memo: e.memo, exact: e.exact, change: e.change };
}

function buildStagePczt(id: string, ss: SignedStage, out: string, payments = ss.instruction.payments) {
  const w = join(jobDir(id), "wallet");
  const ins = ss.instruction;
  const uri = zip321Uri(payments.map((p, i) => ({ to: p.to, amount_zat: p.zat, memo: i === 0 ? ins.memo : `${ins.memo} ${p.party}` })));
  devtool(["pczt", "-w", w, "create", "--payment-uri", uri, "--target-note-count", "1", "--output", out], { quiet: true });
  devtool(["pczt", "-w", w, "prove", out, "--output", out.replace(/\.pczt$/, ".proven.pczt")], { quiet: true });
  return out.replace(/\.pczt$/, ".proven.pczt");
}

async function waitEscrow(id: string, zat: number) {
  const ew = join(jobDir(id), "wallet");
  if (!TESTNET) { await mine(10); await waitIndexer(); }
  await waitChain(`the escrow's ${fmt(zat)} to be spendable`, () => { const b = balance(ew); return { ok: b.ironwood >= zat, tip: b.tip }; }, 120);
}

/** Plan, sign (operator), check (each signer), build, co-sign (operator + policy) and broadcast one stage. */
export async function runStage(id: string, stage: StageKind, quote: SignedQuote, recipient?: RecipientBinding,
  opts: { showDiversion?: boolean; fixtures?: string } = {}): Promise<StageRecord> {
  let d = loadDeal(id);
  const st = dealState(d);
  const ins = planStage(st, { stage, quote, recipient });
  const ss = signStage(ins, operatorKey());
  writeFileSync(join(jobDir(id), `stage-${ins.seq}.json`), JSON.stringify(ss, null, 2));
  say(`== deal ${id}: stage ${ins.stage_id} (${ins.transition.event}), $${(ins.fiat_usd_cents / 100).toFixed(2)} at $${(quote.quote.price_micros / 1e6).toFixed(2)}/ZEC`);
  say(`  due ${ins.due_zat} zat, tranche ${ins.tranche_zat} zat; pays ${ins.payments.map((p) => `${p.party} ${p.zat}`).join(", ")}; network fee ${ins.network_fee_zat}; change ${ins.change?.zat ?? 0} back to the escrow`);
  if (ins.reserve_topup) say(`  ZEC fell: the marketplace reserve owes the ${ins.reserve_topup.party} ${ins.reserve_topup.zat} zat outside the escrow`);
  await waitEscrow(id, st.escrow_zat);
  const pczt = join(jobDir(id), `stage-${ins.seq}.pczt`);
  if (opts.showDiversion && ins.change) {
    // Someone builds the stage with the remainder paid to another address (the marketplace's own)
    // instead of back to the escrow. The signers' `--change-to-group` check refuses it.
    say("  try: build this stage with the remainder sent to the marketplace's own address instead of back to the escrow");
    const bad = buildStagePczt(id, ss, join(jobDir(id), `stage-${ins.seq}-diverted.pczt`),
      // One more paying output (and the wallet's zero change): the network fee rises by 5,000 zat.
      [...ins.payments, { to: d.terms.fee_address, party: "marketplace_fee", zat: ins.change.zat - 5_000, purpose: "surplus" }]);
    try {
      checkPayout(bad, signerExpect(d, ss, "policy"), d.terms.group_ak);
      throw new Error("policy co-signer accepted a diverted remainder (unexpected)");
    } catch (e) {
      if (/unexpected/.test(String(e))) throw e;
      say(`  -> policy co-signer refuses: ${/Error: (.*)/.exec((e as Error).message)?.[1] ?? (e as Error).message}`);
    }
    if (opts.fixtures) writeFileSync(join(opts.fixtures, "stage-diverted.proven.pczt"), readFileSync(bad));
  }
  const proven = buildStagePczt(id, ss, pczt);
  if (opts.fixtures) writeFileSync(join(opts.fixtures, `stage-${ins.seq}.proven.pczt`), readFileSync(proven));
  // Each signer checks the instruction against its own replica and ledger once, then signs every
  // spend of this stage's PCZT under that policy and records the stage id as used.
  const expects = { operator: signerExpect(d, ss, "operator"), policy: signerExpect(d, ss, "policy") } as Record<Party, Expect>;
  const signed = await frostSign({ id }, ["operator", "policy"], proven, (p) => expects[p], (p) => recordSigned(p, ins.stage_id));
  const w = join(jobDir(id), "wallet");
  const txid = devtool(["pczt", "-w", w, "send", "-s", LIGHTWALLETD, signed]).trim().split("\n").pop()!;
  let height: number | undefined;
  if (TESTNET) {
    say(`  stage tx ${txid} broadcast`);
    await waitChain("the stage to be mined", () => { const b = balance(w); height = minedHeight(w, txid); return { ok: height !== undefined, tip: b.tip }; });
    say(`  stage mined at height ${height}`);
  } else {
    await mine(10);
    await waitIndexer();
  }
  d = loadDeal(id);
  const rec: StageRecord = { after_event: st.event_seq, stage: ss, txid, height };
  const next = applyStage(st, ss);
  d.stages.push(rec);
  saveDeal(d);
  say(`  executed; shares ${JSON.stringify(next.shares)}, escrow ${fmt(next.escrow_zat)}${next.status === "closed" ? " (empty, deal closed)" : ""}`);
  return rec;
}

/** Pay a stage's shortfall from the marketplace's reserve wallet (an ordinary shielded send). */
export async function payTopup(id: string, seq: number, maxMinutes = 45): Promise<string | undefined> {
  const d = loadDeal(id);
  const rec = d.stages.find((r) => r.stage.instruction.seq === seq);
  const t = rec?.stage.instruction.reserve_topup;
  if (!rec || !t) return undefined;
  const need = t.zat + 15_000;
  const rw = walletDir("reserve");
  say(`== deal ${id}: reserve tops up the ${t.party}: ${t.zat} zat (stage ${rec.stage.instruction.stage_id})`);
  try {
    await waitChain(`the reserve to have ${fmt(need)} spendable`, () => { const b = balance(rw); return { ok: b.ironwood >= need, tip: b.tip }; }, maxMinutes);
  } catch (e) {
    say(`  reserve top-up not sent: ${(e as Error).message}`);
    return undefined;
  }
  const out = devtool(["wallet", "-w", rw, "send", "-i", ageFile("reserve"), "--address", t.to, "--value", String(t.zat),
    "--memo", `zescrow topup ${rec.stage.instruction.stage_id}`, "-s", LIGHTWALLETD]);
  rec.topup_txid = out.trim().split("\n").pop();
  saveDeal(d);
  say(`  top-up tx ${rec.topup_txid}`);
  return rec.topup_txid;
}

/**
 * The CrowdStore scenario (testnet path M): $2.00 deal funded at $40/ZEC; seller paid 95% at $44
 * (surplus to the reserve, change back to the escrow); a negative review after that payout
 * freezes nothing already paid and makes the 4% reward claimable; the buyer claims it at $38
 * (shortfall topped up by the reserve); the marketplace collects its 1% at $40 and the escrow
 * ends empty. Also shows two refusals: a remainder diverted away from the escrow, and a replay.
 */
export async function marketplaceScenario(opts: { fixtures?: string; resume?: string } = {}) {
  const id = opts.resume ?? `M-${Date.now().toString(36)}`;
  const q = quoteSigner();
  const t0 = Date.now();
  if (!opts.resume) createDeal(id, 200);
  await fundDeal(id, q.quote(40_000_000));

  if (!dealState(loadDeal(id)).delivered) {
    say("  try: seller payout before delivery");
    try { planStage(dealState(loadDeal(id)), { stage: "seller_payout", quote: q.quote(40_000_000), recipient: bindAddress("seller", partyAddress("seller")) }); }
    catch (e) { say(`  -> refused: ${(e as Error).message}`); }
    operatorEvent(id, { type: "delivered" });
  } else say("  resumed: funded and delivered");

  const seller = bindAddress("seller", partyAddress("seller"));
  const buyer = bindAddress("buyer", partyAddress("buyer"));
  const s1 = await runStage(id, "seller_payout", q.quote(44_000_000), seller, { showDiversion: true, fixtures: opts.fixtures });

  say("  try: replay stage 1 (same signed instruction)");
  try { checkStage(dealState(loadDeal(id)), s1.stage, { signed: signedStages("policy") }); }
  catch (e) { say(`  -> policy co-signer refuses: ${(e as Error).message}`); }

  operatorEvent(id, { type: "review", sentiment: "negative" });
  say("  negative review after the seller payout: nothing already paid is frozen or reversed; the reward is claimable");
  await runStage(id, "reward_payout", q.quote(38_000_000), buyer);
  await runStage(id, "fee_payout", q.quote(40_000_000));
  const topup = await payTopup(id, 2);

  const d = loadDeal(id);
  const st = dealState(d);
  say(`== summary (${NETWORK}) deal ${id}: ${st.status}, shares ${JSON.stringify(st.shares)}, escrow ${fmt(balance(join(jobDir(id), "wallet")).total)}`);
  say(`  fund tx ${d.fund_txid} @${d.fund_height}`);
  for (const r of d.stages) say(`  ${r.stage.instruction.stage_id.padEnd(28)} tx ${r.txid} @${r.height}`);
  if (topup) say(`  reserve top-up tx ${topup}`);
  for (const l of st.log) say(`  log: ${l}`);
  say(`  done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
}
