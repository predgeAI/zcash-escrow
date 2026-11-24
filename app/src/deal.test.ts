import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEAL_SCHEMA, DEFAULT_NETWORK_FEE_BUDGET_ZAT, DEFAULT_SPLIT, IllegalTransition, STAGE_SCHEMA, addressMessage, applyEvent, applyStage,
  checkStage, newDeal, planStage, replay, signEvent, signStage, splitAmount, stateHash,
  type DealEvent, type DealState, type DealTerms, type RecipientBinding, type SignedEvent, type SignedStage, type StageKind,
} from "./deal.ts";
import { signQuote } from "./pricelock.ts";
import { loadArbiterKey, signCanonical } from "./verdict.ts";

const dir = mkdtempSync(join(tmpdir(), "zdeal-"));
const key = (n: string) => loadArbiterKey(join(dir, `${n}.pem`));
const OP = key("operator");
const ARB = key("arbiter");
const QK = key("quote");
const OTHER = key("other");

const T0 = Date.parse("2026-11-24T12:00:00Z");
const at = (min: number) => new Date(T0 + min * 60_000);
const usd = (d: number) => Math.round(d * 1e6);
const quote = (price: number, min = 0, k = QK) => signQuote(k, usd(price), at(min));

const SELLER = "utest1seller";
const BUYER = "utest1buyer";
const FEE = "utest1fee";
const RESERVE = "utest1reserve";
const UFVK = "uviewtest1escrow";

function terms(extra: Partial<DealTerms> = {}): DealTerms {
  return {
    schema: DEAL_SCHEMA, deal_id: "M-test", amount_usd_cents: 200, split: DEFAULT_SPLIT,
    fee_address: FEE, reserve_address: RESERVE, escrow_address: "utest1escrow", escrow_ufvk: UFVK, group_ak: "ab".repeat(32),
    operator_pubkey: OP.pubHex, arbiter_pubkey: ARB.pubHex, quote_pubkey: QK.pubHex,
    quote_max_age_s: 900, price_tolerance_bps: 100, network_fee_budget_zat: DEFAULT_NETWORK_FEE_BUDGET_ZAT, ...extra,
  };
}

/** A deal driven through signed events and executed stages, the way every signer replays it. */
class Deal {
  events: SignedEvent[] = [];
  stages: { after_event: number; stage: SignedStage }[] = [];
  s: DealState;
  min = 0;
  constructor(public t = terms()) { this.s = newDeal(t); }
  ev(e: DealEvent, issuer: "operator" | "arbiter" = "operator") {
    const k = issuer === "operator" ? OP : ARB;
    const se = signEvent(this.s, e, issuer, k, at(++this.min));
    this.s = applyEvent(this.s, se);
    this.events.push(se);
    return se;
  }
  fund(price = 40, zat?: number) {
    const q = quote(price, this.min + 1);
    return this.ev({ type: "funded", funded_zat: zat ?? 5_045_000, quote: q, paid_at: q.quote.issued_at });
  }
  plan(stage: StageKind, price: number, recipient?: RecipientBinding) {
    return planStage(this.s, { stage, quote: quote(price, this.min), recipient, at: at(this.min) });
  }
  /** Operator plans and signs; the signer checks against its own state; the stage executes. */
  stage(stage: StageKind, price: number, recipient?: RecipientBinding) {
    const ss = signStage(this.plan(stage, price, recipient), OP);
    const expect = checkStage(this.s, ss, { now: at(this.min) });
    this.stages.push({ after_event: this.s.event_seq, stage: ss });
    this.s = applyStage(this.s, ss);
    return { ss, ins: ss.instruction, expect };
  }
}

const bind = (party: RecipientBinding["party"], address: string, sig?: string): RecipientBinding =>
  ({ party, address, attested_by: "operator", source: "crowdstore account", ...(sig ? { party_signature: sig } : {}) });
const seller = bind("seller", SELLER);
const buyer = bind("buyer", BUYER);

const pays = (ins: { payments: { party: string; zat: number }[] }) => ins.payments.map((p) => [p.party, p.zat]);
const throwsIllegal = (f: () => unknown, re: RegExp) => assert.throws(f, (e: Error) => e instanceof IllegalTransition && re.test(e.message), re.source);

test("fiat terms: 9500/400/100 bps of the fiat amount and of the ZEC principal at the funding quote", () => {
  const d = new Deal();
  d.fund(40);
  assert.deepEqual(d.s.fiat_cents, { seller: 190, reward: 8, fee: 2 });
  assert.equal(d.s.principal_zat, 5_000_000);
  assert.deepEqual(d.s.tranche_zat, { seller: 4_750_000, reward: 200_000, fee: 50_000 });
  assert.equal(d.s.escrow_zat, 5_045_000);
  assert.deepEqual(splitAmount(101, DEFAULT_SPLIT), { seller: 95, reward: 4, fee: 2 });
});

test("funding must be exactly principal + network fee budget, at a fresh quote from the terms' quote key", () => {
  throwsIllegal(() => new Deal().fund(40, 5_000_000), /expected 5045000/);
  const d = new Deal();
  const fund = (q: ReturnType<typeof quote>, paidAt: Date) => ({ type: "funded" as const, funded_zat: 5_045_000, quote: q, paid_at: paidAt.toISOString() });
  throwsIllegal(() => d.ev(fund(quote(40, 0, OTHER), at(0))), /key the deal terms do not name/);
  throwsIllegal(() => new Deal().ev(fund(quote(40, -60), at(0))), /older than the 900 s/);
  // Confirmations may take longer than a quote lives: freshness is judged when the buyer paid.
  const slow = new Deal();
  slow.min = 30;
  slow.ev(fund(quote(40, 0), at(1)));
  assert.equal(slow.s.status, "funded");
  throwsIllegal(() => new Deal().ev(fund(quote(40, 0), at(10))), /paid_at is missing or after the event/);
  const f = new Deal();
  f.fund();
  throwsIllegal(() => f.fund(), /already funded/);
});

test("CrowdStore path: seller 95% (ZEC up), negative review after payout, reward 4% (ZEC down), fee 1%, escrow empty", () => {
  const d = new Deal();
  d.fund(40);
  throwsIllegal(() => d.plan("seller_payout", 44, seller), /seller share is locked/);
  d.ev({ type: "delivered" });

  // ZEC rose 10%: the seller gets $1.90 worth, the rest of its tranche goes to the reserve.
  const s1 = d.stage("seller_payout", 44, seller);
  assert.deepEqual(pays(s1.ins), [["seller", 4_318_181], ["reserve", 431_819]]);
  assert.equal(s1.ins.network_fee_zat, 15_000);
  assert.deepEqual(s1.ins.change, { to: "escrow-internal", zat: 280_000 });
  assert.equal(s1.ins.reserve_topup, null);
  assert.deepEqual(s1.expect, {
    to: SELLER, min: 4_318_181, max: 4_318_181, memo: s1.ins.memo, exact: [{ to: RESERVE, zat: 431_819 }], change: { ufvk: UFVK, exact: 280_000 },
  });
  assert.equal(d.s.shares.seller, "paid");
  assert.equal(d.s.shares.fee, "payable");

  // A negative review after the payout: nothing already paid is frozen or reversed; the reward is claimable.
  d.ev({ type: "review", sentiment: "negative" });
  assert.equal(d.s.shares.seller, "paid");
  assert.equal(d.s.shares.reward, "payable");

  // ZEC fell 5%: the escrow pays the whole tranche and the reserve owes the buyer the shortfall.
  const s2 = d.stage("reward_payout", 38, buyer);
  assert.deepEqual(pays(s2.ins), [["buyer", 200_000]]);
  assert.equal(s2.ins.due_zat, 210_526);
  assert.deepEqual(s2.ins.reserve_topup, { to: BUYER, party: "buyer", zat: 10_526 });
  assert.equal(s2.ins.network_fee_zat, 10_000);
  assert.deepEqual(s2.ins.change, { to: "escrow-internal", zat: 70_000 });

  // The fee empties the escrow: unused network fee budget goes to the reserve, no change.
  const s3 = d.stage("fee_payout", 40);
  assert.deepEqual(pays(s3.ins), [["marketplace_fee", 50_000], ["reserve", 5_000]]);
  assert.equal(s3.ins.network_fee_zat, 15_000);
  assert.equal(s3.ins.change, null);
  assert.equal(s3.expect.change, undefined);
  assert.equal(d.s.escrow_zat, 0);
  assert.equal(d.s.status, "closed");
  throwsIllegal(() => d.plan("reward_payout", 40, buyer), /closed/);
  // Every party gets the same state from the signed log.
  assert.equal(stateHash(replay(d.t, d.events, d.stages)), stateHash(d.s));
});

test("negative review before payout freezes the seller; the reward is claimable before the seller is paid; an update releases", () => {
  const d = new Deal();
  d.fund();
  throwsIllegal(() => d.plan("reward_payout", 40, buyer), /no verified review yet/);
  throwsIllegal(() => d.ev({ type: "review", sentiment: "negative" }), /delivered item/);
  d.ev({ type: "delivered" });
  d.ev({ type: "review", sentiment: "negative" });
  assert.equal(d.s.shares.seller, "frozen");
  throwsIllegal(() => d.plan("seller_payout", 40, seller), /frozen by a negative review/);
  throwsIllegal(() => d.plan("fee_payout", 40), /only after the seller is paid/);
  const r = d.stage("reward_payout", 40, buyer); // before the seller payout
  assert.deepEqual(pays(r.ins), [["buyer", 200_000]]);
  throwsIllegal(() => d.plan("reward_payout", 40, buyer), /reward is paid/);
  throwsIllegal(() => d.ev({ type: "review", sentiment: "positive" }), /already reviewed/);
  d.ev({ type: "review_updated", sentiment: "positive" });
  assert.equal(d.s.shares.seller, "payable");
  d.stage("seller_payout", 40, seller);
  d.stage("fee_payout", 40);
  assert.equal(d.s.status, "closed");
});

test("an updated review never reverses a payout; it only freezes or releases what is unpaid", () => {
  const d = new Deal();
  d.fund();
  d.ev({ type: "delivered" });
  throwsIllegal(() => d.ev({ type: "review_updated", sentiment: "positive" }), /no review to update/);
  d.ev({ type: "review", sentiment: "positive" });
  assert.equal(d.s.shares.seller, "payable");
  d.ev({ type: "review_updated", sentiment: "negative" });
  assert.equal(d.s.shares.seller, "frozen");
  d.ev({ type: "review_updated", sentiment: "positive" });
  d.stage("seller_payout", 40, seller);
  d.ev({ type: "review_updated", sentiment: "negative" });
  assert.equal(d.s.shares.seller, "paid");
});

test("full refund: 100% of the fiat value at the refund quote, fee not kept, escrow empty", () => {
  // ZEC fell to $32: 200 cents is 6_250_000 zat; the escrow holds 5_000_000 + budget.
  const d = new Deal();
  d.fund(40);
  const r = d.stage("refund", 32, buyer);
  assert.deepEqual(r.ins.transition.shares, ["seller", "reward", "fee"]);
  assert.equal(r.ins.fiat_usd_cents, 200);
  assert.equal(r.ins.due_zat, 6_250_000);
  assert.deepEqual(pays(r.ins), [["buyer", 5_000_000], ["reserve", 30_000]]);
  assert.deepEqual(r.ins.reserve_topup, { to: BUYER, party: "buyer", zat: 1_250_000 });
  assert.equal(r.ins.change, null);
  assert.deepEqual(d.s.shares, { seller: "refunded", reward: "refunded", fee: "waived" });
  assert.equal(d.s.status, "closed");

  // ZEC rose to $50: the buyer gets $2.00 = 4_000_000 zat, the rest goes to the reserve.
  const u = new Deal();
  u.fund(40);
  const ru = u.stage("refund", 50, buyer);
  assert.deepEqual(pays(ru.ins), [["buyer", 4_000_000], ["reserve", 1_030_000]]);
  assert.equal(ru.ins.reserve_topup, null);
});

test("refund after the seller is paid needs an arbiter decision, and returns only what is unpaid", () => {
  const d = new Deal();
  d.fund();
  d.ev({ type: "delivered" });
  d.stage("seller_payout", 40, seller);
  throwsIllegal(() => d.plan("refund", 40, buyer), /needs an arbiter decision/);
  d.ev({ type: "dispute_opened", by: "buyer", reason: "item not as described" });
  throwsIllegal(() => d.ev({ type: "dispute_resolved", decision: "refund_buyer", reasons: [] }, "operator"), /only the arbiter|must be issued/);
  d.ev({ type: "dispute_resolved", decision: "refund_buyer", reasons: ["seller agreed to refund the rest"] }, "arbiter");
  throwsIllegal(() => d.plan("fee_payout", 40), /only the refund stage/);
  const r = d.stage("refund", 40, buyer);
  assert.deepEqual(r.ins.transition.shares, ["reward", "fee"]);
  assert.equal(r.ins.fiat_usd_cents, 10);
  assert.deepEqual(pays(r.ins), [["buyer", 250_000], ["reserve", 20_000]]);
  assert.equal(d.s.shares.seller, "paid");
  assert.equal(d.s.status, "closed");
});

test("dispute: nothing signs until the arbiter resolves it", () => {
  const d = new Deal();
  d.fund();
  d.ev({ type: "delivered" });
  d.ev({ type: "review", sentiment: "negative" });
  const before = signStage(d.plan("reward_payout", 40, buyer), OP);
  d.ev({ type: "dispute_opened", by: "seller", reason: "review is fake" });
  for (const [k, r] of [["seller_payout", seller], ["reward_payout", buyer], ["fee_payout", undefined], ["refund", buyer]] as const)
    throwsIllegal(() => d.plan(k, 40, r), /dispute open/);
  // An instruction signed before the dispute is refused as well (planned from another state).
  throwsIllegal(() => checkStage(d.s, before, { now: at(d.min) }), /dispute open|seq|another/);
  throwsIllegal(() => d.ev({ type: "dispute_opened", by: "buyer", reason: "x" }), /already open/);
  d.ev({ type: "dispute_resolved", decision: "release_seller", reasons: ["review is genuine but the item was delivered"] }, "arbiter");
  assert.equal(d.s.shares.seller, "payable");
  d.stage("seller_payout", 40, seller);
});

test("replay: a stage id executes once, events are one-shot and ordered", () => {
  const d = new Deal();
  d.fund();
  d.ev({ type: "delivered" });
  const s1 = d.stage("seller_payout", 40, seller);
  throwsIllegal(() => checkStage(d.s, s1.ss, { now: at(d.min) }), /already executed: replay refused/);
  throwsIllegal(() => applyStage(d.s, s1.ss), /already executed/);
  // A signer's own ledger refuses a stage it already signed, even before execution is recorded.
  const fresh = new Deal();
  fresh.fund();
  fresh.ev({ type: "delivered" });
  const ss = signStage(fresh.plan("seller_payout", 40, seller), OP);
  throwsIllegal(() => checkStage(fresh.s, ss, { now: at(fresh.min), signed: [ss.instruction.stage_id] }), /replay refused/);
  // Event replay.
  throwsIllegal(() => applyEvent(d.s, d.events[1]), /replayed or out of order/);
});

test("signers refuse instructions that differ from the plan, are not the issuer's, or use a bad quote", () => {
  const d = new Deal();
  d.fund();
  d.ev({ type: "delivered" });
  const ins = d.plan("seller_payout", 44, seller);
  const now = { now: at(d.min) };
  // Remainder diverted: change lowered and paid elsewhere, re-signed by the operator.
  const diverted = structuredClone(ins);
  diverted.change = { to: "escrow-internal", zat: 1 };
  diverted.payments.push({ to: "utest1attacker", party: "reserve", zat: 279_999, purpose: "surplus" });
  throwsIllegal(() => checkStage(d.s, signStage(diverted, OP), now), /does not match/);
  // Seller overpaid.
  const over = structuredClone(ins);
  over.payments[0].zat += 1;
  throwsIllegal(() => checkStage(d.s, signStage(over, OP), now), /does not match/);
  // Not the operator's signature.
  throwsIllegal(() => checkStage(d.s, { instruction: ins, signature: signCanonical(ins, OTHER) }, now), /signature is not the operator's/);
  // Quote too old at signing time, and a quote far from the signer's own reference price.
  throwsIllegal(() => checkStage(d.s, signStage(ins, OP), { now: at(d.min + 30) }), /older than/);
  assert.throws(() => checkStage(d.s, signStage(ins, OP), { now: at(d.min), reference_price_micros: usd(40) }), /bps from the signer's reference/);
  checkStage(d.s, signStage(ins, OP), { now: at(d.min), reference_price_micros: usd(43.8) });
  // Wrong schema.
  throwsIllegal(() => checkStage(d.s, signStage({ ...ins, schema: "predge.zescrow.verdict/2" as typeof STAGE_SCHEMA }, OP), now), /not a stage/);
});

test("late payout addresses: bound in the instruction, attested by the operator, signed by the party when it has a key", () => {
  const SK = key("seller-account");
  const d = new Deal(terms({ party_keys: { seller: SK.pubHex } }));
  d.fund();
  d.ev({ type: "delivered" });
  throwsIllegal(() => d.plan("seller_payout", 40), /needs the seller's payout address/);
  throwsIllegal(() => d.plan("seller_payout", 40, seller), /not signed by the seller's registered key/);
  const wrongSig = signCanonical(addressMessage("M-test", "seller", "utest1other"), SK);
  throwsIllegal(() => d.plan("seller_payout", 40, bind("seller", SELLER, wrongSig)), /not signed/);
  throwsIllegal(() => d.plan("seller_payout", 40, bind("buyer", SELLER)), /bound for the buyer/);
  throwsIllegal(() => d.plan("seller_payout", 40, bind("seller", FEE)), /marketplace address/);
  const good = bind("seller", SELLER, signCanonical(addressMessage("M-test", "seller", SELLER), SK));
  const s = d.stage("seller_payout", 40, good);
  assert.equal(s.ins.recipient.address, SELLER);
  assert.equal(s.expect.to, SELLER);
});

test("terms validation", () => {
  assert.throws(() => newDeal(terms({ split: { seller_bps: 9_500, reward_bps: 400, fee_bps: 50 } })), /summing to 10000/);
  assert.throws(() => newDeal(terms({ reserve_address: FEE })), /must differ/);
  assert.throws(() => newDeal(terms({ amount_usd_cents: 0 })), /positive integer/);
  assert.throws(() => newDeal(terms({ arbiter_pubkey: OP.pubHex })), /different keys/);
  // A configurable split works the same way.
  const d = new Deal(terms({ split: { seller_bps: 9_000, reward_bps: 500, fee_bps: 500 } }));
  assert.deepEqual(d.s.fiat_cents, { seller: 180, reward: 10, fee: 10 });
});
