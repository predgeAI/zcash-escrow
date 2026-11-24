import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadArbiterKey } from "./verdict.ts";
import { localQuoteSigner } from "./pricelock.ts";
import {
  ORDER_NETWORK_FEE_BUDGET_ZAT, ORDER_SCHEMA, applyOrderEvent, applyOrderStage, checkOrderStage, newOrder, orderFundingZat, planOrderStage,
  signOrderEvent, signOrderStage, type OrderState, type OrderTerms,
} from "./milestones.ts";

const dir = mkdtempSync(join(tmpdir(), "ms-"));
const op = loadArbiterKey(join(dir, "op.pem"));
const arb = loadArbiterKey(join(dir, "arb.pem"));
const q = localQuoteSigner(join(dir, "q.pem"));
const H = "a".repeat(64);

const terms = (): OrderTerms => ({
  schema: ORDER_SCHEMA, order_id: "OP-test", amount_usd_cents: 20_000, split: { preview: 2_500, acceptance: 7_500 },
  definitions: { preview: "working preview link sent to the client", acceptance: "client confirms in writing" },
  seller_address: "u-seller", buyer_refund_address: "u-buyer", reserve_address: "u-reserve", escrow_address: "u-escrow",
  escrow_ufvk: "uview", group_ak: "ak", operator_pubkey: op.pubHex, arbiter_pubkey: arb.pubHex, quote_pubkey: q.pubHex,
  quote_max_age_s: 900, price_tolerance_bps: 100, network_fee_budget_zat: ORDER_NETWORK_FEE_BUDGET_ZAT,
});

function funded(): OrderState {
  let s = newOrder(terms());
  const quote = q.quote(4_000_000_000);
  s = applyOrderEvent(s, signOrderEvent(s, { type: "funded", funded_zat: orderFundingZat(s.terms, quote), quote, paid_at: new Date().toISOString() }, "operator", op));
  return s;
}
const ev = (s: OrderState, e: Parameters<typeof signOrderEvent>[1], who: "operator" | "arbiter" = "operator") =>
  applyOrderEvent(s, signOrderEvent(s, e, who, who === "operator" ? op : arb));
const stage = (s: OrderState, kind: "preview_payout" | "acceptance_payout" | "refund") => {
  const ss = signOrderStage(planOrderStage(s, { stage: kind, quote: q.quote(4_000_000_000) }), op);
  checkOrderStage(s, ss);
  return { ss, next: applyOrderStage(s, ss) };
};

test("path A: 25% on preview, 75% on acceptance, escrow empty", () => {
  let s = funded();
  assert.equal(s.escrow_zat, 5_000_000 + 30_000);
  assert.throws(() => planOrderStage(s, { stage: "preview_payout", quote: q.quote(4_000_000_000) }), /locked/);
  s = ev(s, { type: "preview_delivered", evidence_sha256: H, note: "preview" });
  assert.throws(() => planOrderStage(s, { stage: "acceptance_payout", quote: q.quote(4_000_000_000) }), /locked/);
  const p = stage(s, "preview_payout");
  assert.deepEqual(p.ss.instruction.payments.map((x) => [x.party, x.zat]), [["seller", 1_250_000]]);
  assert.equal(p.ss.instruction.change?.zat, 5_030_000 - 1_250_000 - 10_000);
  assert.throws(() => checkOrderStage(p.next, p.ss), /replay/);
  s = ev(p.next, { type: "accepted", evidence_sha256: H, note: "ok" });
  const f = stage(s, "acceptance_payout");
  assert.deepEqual(f.ss.instruction.payments.map((x) => [x.party, x.zat]), [["seller", 3_750_000], ["reserve", 5_000]]);
  assert.equal(f.next.status, "closed");
});

test("path B: preview paid, dispute, arbiter refund, unpaid 75% to the client", () => {
  let s = funded();
  s = ev(s, { type: "preview_delivered", evidence_sha256: H, note: "preview" });
  s = stage(s, "preview_payout").next;
  s = ev(s, { type: "dispute_opened", by: "buyer", reason: "final work does not match the spec" });
  assert.throws(() => planOrderStage(s, { stage: "acceptance_payout", quote: q.quote(4_000_000_000) }), /dispute open/);
  assert.throws(() => planOrderStage(s, { stage: "refund", quote: q.quote(4_000_000_000) }), /dispute open/);
  assert.throws(() => ev(s, { type: "dispute_resolved", decision: "refund_buyer", reasons: ["x"] }, "operator"), /must be issued|only the arbiter/);
  s = ev(s, { type: "dispute_resolved", decision: "refund_buyer", reasons: ["x"] }, "arbiter");
  assert.throws(() => planOrderStage(s, { stage: "acceptance_payout", quote: q.quote(4_000_000_000) }), /only the refund/);
  const r = stage(s, "refund");
  assert.deepEqual(r.ss.instruction.payments.map((x) => [x.party, x.zat]), [["buyer", 3_750_000], ["reserve", 5_000]]);
  assert.equal(r.next.shares.preview, "paid");
  assert.equal(r.next.shares.acceptance, "refunded");
  assert.equal(r.next.status, "closed");
});

test("a tampered instruction is refused", () => {
  let s = funded();
  s = ev(s, { type: "preview_delivered", evidence_sha256: H, note: "preview" });
  const ins = planOrderStage(s, { stage: "preview_payout", quote: q.quote(4_000_000_000) });
  ins.payments[0].to = "u-attacker";
  assert.throws(() => checkOrderStage(s, signOrderStage(ins, op)), /does not match/);
});
