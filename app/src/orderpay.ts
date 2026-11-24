// Milestone orders (milestones.ts) on a real escrow: the ZEC Order Pay test (testnet path OP).
//
// One 2-of-3 FROST escrow per order. Share holders: operator, policy co-signer, arbiter. In this
// test Predge runs all three roles and plays the client; the seller's payout address is the
// partner's own testnet address, fixed in the order terms.
//
//   Order A (normal):  fund -> preview_delivered -> 25% to the seller -> accepted -> 75% to the seller
//   Order B (dispute): fund -> preview_delivered -> 25% to the seller -> dispute_opened ->
//                      arbiter dispute_resolved refund_buyer -> the unpaid 75% back to the client

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkPayout, type Expect } from "./payout-check.ts";
import {
  ORDER_NETWORK_FEE_BUDGET_ZAT, ORDER_SCHEMA, applyOrderEvent, applyOrderStage, checkOrderStage, newOrder, orderFundingZat, planOrderStage,
  replayOrder, signOrderEvent, signOrderStage,
  type OrderEvent, type OrderStageKind, type OrderState, type OrderTerms, type SignedOrderEvent, type SignedOrderStage,
} from "./milestones.ts";
import {
  STATE, ageFile, balance, ensureBuyerFunds, ensureWallet, fmt, frostSign, jobDir, makeEscrowGroup, minedHeight, partyAddress,
  partyDir, waitChain, walletDir, zip321Uri, type Party,
} from "./escrow.ts";
import { quoteSigner } from "./marketplace.ts";
import type { SignedQuote } from "./pricelock.ts";
import { LIGHTWALLETD, NETWORK, TESTNET, devtool, say } from "./tools.ts";
import { canonical, loadArbiterKey, sha256 } from "./verdict.ts";

interface StageRecord { after_event: number; stage: SignedOrderStage; txid: string; height?: number }
export interface Order {
  id: string;
  terms: OrderTerms;
  events: SignedOrderEvent[];
  stages: StageRecord[];
  fund_txid?: string;
  fund_height?: number;
  funding?: { quote: SignedQuote; paid_at: string };
  refusals: { step: string; reason: string }[];
}

const orderFile = (id: string) => join(jobDir(id), "order.json");
export const loadOrder = (id: string): Order => JSON.parse(readFileSync(orderFile(id), "utf8")) as Order;
const saveOrder = (o: Order) => { mkdirSync(jobDir(o.id), { recursive: true }); writeFileSync(orderFile(o.id), JSON.stringify(o, null, 2)); };

const operatorKey = () => loadArbiterKey(join(partyDir("operator"), "operator-ed25519.pem"));
const arbiterKey = () => loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));

export const orderState = (o: Order): OrderState =>
  replayOrder(o.terms, o.events, o.stages.map((r) => ({ after_event: r.after_event, stage: r.stage })));

const ledgerFile = (p: Party) => join(partyDir(p), "order-stage-ledger.json");
const signedStages = (p: Party): string[] => (existsSync(ledgerFile(p)) ? (JSON.parse(readFileSync(ledgerFile(p), "utf8")) as string[]) : []);
function recordSigned(p: Party, id: string) {
  const l = signedStages(p);
  if (!l.includes(id)) writeFileSync(ledgerFile(p), JSON.stringify([...l, id], null, 2));
}

export function createOrder(id: string, amountUsdCents: number, sellerAddress: string): Order {
  const reserve = ensureWallet("reserve");
  const buyer = partyAddress("buyer");
  const g = makeEscrowGroup(id, ["operator", "policy", "arbiter"]);
  const terms: OrderTerms = {
    schema: ORDER_SCHEMA, order_id: id, amount_usd_cents: amountUsdCents, split: { preview: 2_500, acceptance: 7_500 },
    definitions: {
      preview: "preview delivered: the seller sends the client a working preview link",
      acceptance: "accepted: the client confirms in writing that the final work matches the spec",
    },
    seller_address: sellerAddress, buyer_refund_address: buyer, reserve_address: reserve,
    escrow_address: g.address, escrow_ufvk: g.ufvk, group_ak: g.ak,
    operator_pubkey: operatorKey().pubHex, arbiter_pubkey: arbiterKey().pubHex, quote_pubkey: quoteSigner().pubHex,
    quote_max_age_s: 900, price_tolerance_bps: 100, network_fee_budget_zat: ORDER_NETWORK_FEE_BUDGET_ZAT,
  };
  newOrder(terms);
  const o: Order = { id, terms, events: [], stages: [], refusals: [] };
  saveOrder(o);
  writeFileSync(join(jobDir(id), "terms.json"), JSON.stringify(terms, null, 2));
  say(`== order ${id}: $${(amountUsdCents / 100).toFixed(2)}, split 25% preview / 75% acceptance, terms sha256 ${sha256(canonical(terms))}`);
  say(`  escrow ${g.address}`);
  say(`  FROST 2-of-3 (trusted dealer): operator, policy co-signer, arbiter; group key ${g.ak}`);
  return o;
}

function event(id: string, e: OrderEvent, issuer: "operator" | "arbiter"): SignedOrderEvent {
  const o = loadOrder(id);
  const st = orderState(o);
  const se = signOrderEvent(st, e, issuer, issuer === "operator" ? operatorKey() : arbiterKey());
  const next = applyOrderEvent(st, se);
  o.events.push(se);
  saveOrder(o);
  writeFileSync(join(jobDir(id), `event-${se.envelope.seq}-${e.type}.json`), JSON.stringify(se, null, 2));
  say(`  event ${se.envelope.seq}: ${e.type}${"decision" in e ? ` (${e.decision})` : ""} signed by the ${issuer}; sha256 ${sha256(canonical(se.envelope))}; milestones ${JSON.stringify(next.shares)}`);
  return se;
}

function refuse(id: string, step: string, f: () => unknown) {
  say(`  try: ${step}`);
  try { f(); } catch (e) {
    const reason = (e as Error).message;
    say(`  -> refused: ${reason}`);
    const o = loadOrder(id);
    o.refusals.push({ step, reason });
    saveOrder(o);
    return;
  }
  throw new Error(`${step}: accepted (unexpected)`);
}

export async function fundOrder(id: string, quote: SignedQuote) {
  const o = loadOrder(id);
  const ew = join(jobDir(id), "wallet");
  if (orderState(o).status !== "created") return;
  if (o.funding) quote = o.funding.quote;
  const need = orderFundingZat(o.terms, quote);
  say(`== order ${id}: client funds ${fmt(need)} ($${(o.terms.amount_usd_cents / 100).toFixed(2)} at the demo quote $${(quote.quote.price_micros / 1e6).toFixed(2)}/ZEC + ${o.terms.network_fee_budget_zat} zat network fee budget)`);
  if (!o.fund_txid) {
    await ensureBuyerFunds(need + 20_000);
    o.funding = { quote, paid_at: new Date().toISOString() };
    saveOrder(o);
    const out = devtool(["wallet", "-w", walletDir("buyer"), "send", "-i", ageFile("buyer"), "--address", o.terms.escrow_address,
      "--value", String(need), "--memo", `zescrow fund ${id} terms ${sha256(canonical(o.terms)).slice(0, 16)}`, "-s", LIGHTWALLETD], { quiet: true });
    o.fund_txid = out.trim().split("\n").pop();
    saveOrder(o);
  }
  say(`  fund tx ${o.fund_txid}`);
  await waitChain("the deposit to confirm in the escrow wallet", () => { const b = balance(ew); return { ok: b.ironwood >= need, tip: b.tip }; }, 120);
  o.fund_height = minedHeight(ew, o.fund_txid!);
  saveOrder(o);
  event(id, { type: "funded", funded_zat: balance(ew).ironwood, quote, paid_at: o.funding!.paid_at, fund_txid: o.fund_txid }, "operator");
  say(`  escrow holds ${fmt(need)}, mined at ${o.fund_height}`);
}

function signerExpect(o: Order, ss: SignedOrderStage, p: Party): Expect {
  const e = checkOrderStage(orderState(o), ss, { signed: signedStages(p) });
  return { to: e.to, min: e.min, max: e.max, memo: e.memo, exact: e.exact, change: e.change };
}

function buildPczt(id: string, ss: SignedOrderStage, out: string, payments = ss.instruction.payments) {
  const w = join(jobDir(id), "wallet");
  const ins = ss.instruction;
  const uri = zip321Uri(payments.map((p, i) => ({ to: p.to, amount_zat: p.zat, memo: i === 0 ? ins.memo : `${ins.memo} ${p.party}` })));
  devtool(["pczt", "-w", w, "create", "--payment-uri", uri, "--target-note-count", "1", "--output", out], { quiet: true });
  devtool(["pczt", "-w", w, "prove", out, "--output", out.replace(/\.pczt$/, ".proven.pczt")], { quiet: true });
  return out.replace(/\.pczt$/, ".proven.pczt");
}

export async function runOrderStage(id: string, stage: OrderStageKind, quote: SignedQuote, opts: { showDiversion?: boolean } = {}): Promise<StageRecord> {
  let o = loadOrder(id);
  const st = orderState(o);
  const ss = signOrderStage(planOrderStage(st, { stage, quote }), operatorKey());
  const ins = ss.instruction;
  writeFileSync(join(jobDir(id), `stage-${ins.seq}-${stage}.json`), JSON.stringify(ss, null, 2));
  say(`== order ${id}: stage ${ins.stage_id} (${ins.transition.event}), $${(ins.fiat_usd_cents / 100).toFixed(2)} at $${(quote.quote.price_micros / 1e6).toFixed(2)}/ZEC`);
  say(`  instruction sha256 ${sha256(canonical(ins))}, memo "${ins.memo}"`);
  say(`  pays ${ins.payments.map((p) => `${p.party} ${p.zat}`).join(", ")} zat; network fee ${ins.network_fee_zat}; change ${ins.change?.zat ?? 0} back to the escrow`);
  const w = join(jobDir(id), "wallet");
  await waitChain(`the escrow's ${fmt(st.escrow_zat)} to be spendable`, () => { const b = balance(w); return { ok: b.ironwood >= st.escrow_zat, tip: b.tip }; }, 120);
  if (opts.showDiversion && ins.change) {
    const step = "build this stage with the remainder paid to the reserve (an operator address) instead of back to the escrow";
    say(`  try: ${step}`);
    const bad = buildPczt(id, ss, join(jobDir(id), `stage-${ins.seq}-diverted.pczt`),
      [...ins.payments, { to: o.terms.reserve_address, party: "reserve", zat: ins.change.zat - 5_000, purpose: "surplus" }]);
    try {
      checkPayout(bad, signerExpect(o, ss, "policy"), o.terms.group_ak);
      throw new Error("policy co-signer accepted a diverted remainder (unexpected)");
    } catch (e) {
      if (/unexpected/.test(String(e))) throw e;
      const reason = /Error: (.*)/.exec((e as Error).message)?.[1] ?? (e as Error).message.split("\n").pop()!;
      say(`  -> policy co-signer refuses: ${reason}`);
      o.refusals.push({ step, reason });
      saveOrder(o);
    }
  }
  const proven = buildPczt(id, ss, join(jobDir(id), `stage-${ins.seq}.pczt`));
  const expects = { operator: signerExpect(o, ss, "operator"), policy: signerExpect(o, ss, "policy") } as Record<Party, Expect>;
  const signed = await frostSign({ id }, ["operator", "policy"], proven, (p) => expects[p], (p) => recordSigned(p, ins.stage_id));
  const txid = devtool(["pczt", "-w", w, "send", "-s", LIGHTWALLETD, signed], { quiet: true }).trim().split("\n").pop()!;
  say(`  stage tx ${txid} broadcast`);
  let height: number | undefined;
  await waitChain("the stage to be mined", () => { const b = balance(w); height = minedHeight(w, txid); return { ok: height !== undefined, tip: b.tip }; });
  say(`  stage mined at height ${height}`);
  o = loadOrder(id);
  const rec: StageRecord = { after_event: st.event_seq, stage: ss, txid, height };
  const next = applyOrderStage(st, ss);
  o.stages.push(rec);
  saveOrder(o);
  say(`  executed; milestones ${JSON.stringify(next.shares)}, escrow ${fmt(next.escrow_zat)}${next.status === "closed" ? " (empty, order closed)" : ""}`);
  return rec;
}

const evidence = (s: string) => sha256(s);

/** ZEC Order Pay test: order A (normal) or B (dispute -> refund). */
export async function orderPayScenario(kind: "A" | "B", opts: { seller: string; priceMicros: number; amountCents: number; resume?: string }) {
  if (!TESTNET) throw new Error("path OP runs on testnet");
  const id = opts.resume ?? `OP${kind}-${Date.now().toString(36)}`;
  const q = quoteSigner();
  const t0 = Date.now();
  if (!opts.resume) createOrder(id, opts.amountCents, opts.seller);
  await fundOrder(id, q.quote(opts.priceMicros));
  const st = () => orderState(loadOrder(id));

  if (!st().preview_delivered) {
    refuse(id, "pay the 25% before the preview is delivered", () => planOrderStage(st(), { stage: "preview_payout", quote: q.quote(opts.priceMicros) }));
    const link = `test preview link for order ${id} (placeholder: Predge plays the client in this test)`;
    event(id, { type: "preview_delivered", evidence_sha256: evidence(link), note: "seller sent the client a working preview link (test)" }, "operator");
  }
  if (st().shares.preview !== "paid") {
    refuse(id, "pay the 75% before the client accepted", () => planOrderStage(st(), { stage: "acceptance_payout", quote: q.quote(opts.priceMicros) }));
    const s1 = await runOrderStage(id, "preview_payout", q.quote(opts.priceMicros), { showDiversion: kind === "A" });
    refuse(id, "replay stage 1 (same signed instruction)", () => checkOrderStage(st(), s1.stage, { signed: signedStages("policy") }));
  }

  if (kind === "A") {
    if (!st().accepted) {
      const text = `client confirms in writing that the final work for order ${id} matches the spec (test text)`;
      event(id, { type: "accepted", evidence_sha256: evidence(text), note: "client confirmed in writing (test: Predge as the client)" }, "operator");
    }
    if (st().status !== "closed") await runOrderStage(id, "acceptance_payout", q.quote(opts.priceMicros));
  } else {
    if (!st().disputed && !st().refund_due && st().status !== "closed") {
      event(id, { type: "dispute_opened", by: "buyer", reason: "final work does not match the spec (test)" }, "operator");
      refuse(id, "pay the 75% to the seller while the dispute is open", () => planOrderStage(st(), { stage: "acceptance_payout", quote: q.quote(opts.priceMicros) }));
      refuse(id, "refund while the dispute is open, before the arbiter decides", () => planOrderStage(st(), { stage: "refund", quote: q.quote(opts.priceMicros) }));
      refuse(id, "the operator signs the dispute resolution itself", () => {
        const s = st();
        applyOrderEvent(s, signOrderEvent(s, { type: "dispute_resolved", decision: "release_seller", reasons: ["operator"] }, "arbiter", operatorKey()));
      });
      event(id, { type: "dispute_resolved", decision: "refund_buyer", reasons: ["client's written complaint: final work does not match the spec (test)", "no acceptance on record"] }, "arbiter");
      refuse(id, "after the refund decision, pay the 75% to the seller anyway", () => planOrderStage(st(), { stage: "acceptance_payout", quote: q.quote(opts.priceMicros) }));
    }
    if (st().status !== "closed") await runOrderStage(id, "refund", q.quote(opts.priceMicros));
  }

  const o = loadOrder(id);
  const s = orderState(o);
  say(`== summary (${NETWORK}) order ${id}: ${s.status}, milestones ${JSON.stringify(s.shares)}, escrow ${fmt(balance(join(jobDir(id), "wallet")).total)}`);
  say(`  fund tx ${o.fund_txid} @${o.fund_height}`);
  for (const r of o.stages) say(`  ${r.stage.instruction.stage_id.padEnd(30)} tx ${r.txid} @${r.height}`);
  for (const l of s.log) say(`  log: ${l}`);
  say(`  done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
  return id;
}

export const ORDERPAY_STATE = STATE;
