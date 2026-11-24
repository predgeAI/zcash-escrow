import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FEE_ALLOWANCE_ZAT, adjudicate, loadArbiterKey, marketplaceFeeZat, sha256, signVerdict, splitPayout,
  validateMarketplaceFee, verdictPayments, verifyVerdict, type Terms, type Verdict,
} from "./verdict.ts";
import { zip321Uri } from "./escrow.ts";
import { expectFromPayments } from "./payout-check.ts";

const terms: Terms = {
  item: "x", price_zat: 1, item_sha256: sha256("good"), deliver_by: "2030-01-01T00:00:00Z",
  buyer_refund_address: "B", seller_payout_address: "S",
};
const ev = (party: "buyer" | "seller", kind: string, body: string, at = "2029-01-01T00:00:00Z") =>
  ({ party, kind, note: "", sha256: sha256(body), submitted_at: at });

test("matching on-time delivery pays the seller", () => {
  assert.equal(adjudicate(terms, [ev("seller", "delivery", "good")]).decision, "release_to_seller");
});
test("no delivery, wrong file, or late delivery refunds the buyer", () => {
  assert.equal(adjudicate(terms, []).decision, "refund_buyer");
  assert.equal(adjudicate(terms, [ev("seller", "delivery", "bad")]).decision, "refund_buyer");
  assert.equal(adjudicate(terms, [ev("seller", "delivery", "good", "2031-01-01T00:00:00Z")]).decision, "refund_buyer");
});
test("verdict signatures verify and detect tampering or a different arbiter", () => {
  const k = loadArbiterKey(join(mkdtempSync(join(tmpdir(), "zv-")), "k.pem"));
  const other = loadArbiterKey(join(mkdtempSync(join(tmpdir(), "zv-")), "k.pem"));
  const v = {
    schema: "predge.zescrow.verdict/1", job_id: "j", escrow_address: "E", group_ak: "00", terms_sha256: "t",
    decision: "refund_buyer", reasons: [], evidence: [], payout: { to: "B", party: "buyer", min_amount_zat: 1 },
    cosigner_with: "buyer", issued_at: "now", arbiter_pubkey: k.pubHex,
  } as Verdict;
  const sv = signVerdict(v, k);
  assert.ok(verifyVerdict(sv, k.pubHex));
  assert.ok(!verifyVerdict(sv, other.pubHex));
  assert.ok(!verifyVerdict({ ...sv, verdict: { ...v, decision: "release_to_seller" } }));
});

// ---------- verdict schema /1 and /2 ----------

const base = {
  job_id: "j", escrow_address: "E", group_ak: "00", terms_sha256: "t", decision: "refund_buyer" as const,
  reasons: [], evidence: [], cosigner_with: "buyer" as const, issued_at: "now",
};
test("a /1 verdict still verifies and reads as a single payment", () => {
  const k = loadArbiterKey(join(mkdtempSync(join(tmpdir(), "zv-")), "k.pem"));
  const v: Verdict = { schema: "predge.zescrow.verdict/1", ...base, payout: { to: "B", party: "buyer", min_amount_zat: 5 }, arbiter_pubkey: k.pubHex };
  assert.ok(verifyVerdict(signVerdict(v, k), k.pubHex));
  assert.deepEqual(verdictPayments(v), [{ to: "B", party: "buyer", min_amount_zat: 5 }]);
});
test("a /2 verdict signs over its payment list; changing the fee output breaks the signature", () => {
  const k = loadArbiterKey(join(mkdtempSync(join(tmpdir(), "zv-")), "k.pem"));
  const payments = [
    { to: "B", party: "buyer" as const, min_amount_zat: 80, max_amount_zat: 100 },
    { to: "M", party: "marketplace" as const, min_amount_zat: 7, max_amount_zat: 7 },
  ];
  const v: Verdict = { schema: "predge.zescrow.verdict/2", ...base, payments, arbiter_pubkey: k.pubHex };
  const sv = signVerdict(v, k);
  assert.ok(verifyVerdict(sv, k.pubHex));
  assert.deepEqual(verdictPayments(v), payments);
  const altered = { ...v, payments: [payments[0], { ...payments[1], to: "X" }] };
  assert.ok(!verifyVerdict({ ...sv, verdict: altered }));
});

// ---------- marketplace fee split ----------

const feeTerms = (fee: Terms["marketplace_fee"], price = 5_000_000): Terms => ({ ...terms, price_zat: price, marketplace_fee: fee });

test("bps fee rounds down; the seller gets the rest", () => {
  assert.equal(marketplaceFeeZat(feeTerms({ address: "M", bps: 250, on_refund: "keep" })), 125_000);
  // 333 bps of 1,000,001 zat = 33,300.0333 -> 33,300
  assert.equal(marketplaceFeeZat(feeTerms({ address: "M", bps: 333, on_refund: "keep" }, 1_000_001)), 33_300);
  // 1 bps of 9,999 zat = 0.9999 -> 0 (no fee output)
  assert.equal(marketplaceFeeZat(feeTerms({ address: "M", bps: 1, on_refund: "keep" }, 9_999)), 0);
  // large amounts stay exact (BigInt): 21M ZEC at 9,999 bps
  assert.equal(marketplaceFeeZat(feeTerms({ address: "M", bps: 9_999, on_refund: "keep" }, 2_100_000_000_000_000)), 2_099_790_000_000_000);
  const p = splitPayout(feeTerms({ address: "M", bps: 333, on_refund: "keep" }, 1_000_001), 1_000_001, "seller");
  assert.deepEqual(p, [
    { to: "S", party: "seller", min_amount_zat: 1_000_001 - 33_300 - FEE_ALLOWANCE_ZAT, max_amount_zat: 966_701 },
    { to: "M", party: "marketplace", min_amount_zat: 33_300, max_amount_zat: 33_300 },
  ]);
  assert.equal(p[0].max_amount_zat! + p[1].max_amount_zat!, 1_000_001);
});
test("fixed fee, and refund policy keep vs return", () => {
  const keep = feeTerms({ address: "M", fixed_zat: 40_000, on_refund: "keep" });
  assert.deepEqual(splitPayout(keep, 5_000_000, "buyer").map((p) => [p.party, p.max_amount_zat]), [["buyer", 4_960_000], ["marketplace", 40_000]]);
  const ret = feeTerms({ address: "M", fixed_zat: 40_000, on_refund: "return" });
  assert.deepEqual(splitPayout(ret, 5_000_000, "buyer"), [{ to: "B", party: "buyer", min_amount_zat: 5_000_000 - FEE_ALLOWANCE_ZAT, max_amount_zat: 5_000_000 }]);
  assert.equal(splitPayout(ret, 5_000_000, "seller").length, 2);
});
test("no marketplace fee: one payment, as before", () => {
  assert.deepEqual(splitPayout(terms, 1_000_000, "seller"), [{ to: "S", party: "seller", min_amount_zat: 980_000, max_amount_zat: 1_000_000 }]);
});
test("invalid fee terms are rejected", () => {
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "M", on_refund: "keep" })), /exactly one/);
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "M", bps: 1, fixed_zat: 1, on_refund: "keep" })), /exactly one/);
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "M", bps: 10_001, on_refund: "keep" })), /bps/);
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "M", bps: 2.5, on_refund: "keep" })), /bps/);
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "S", bps: 100, on_refund: "keep" })), /differ/);
  assert.throws(() => validateMarketplaceFee(feeTerms({ address: "M", bps: 100, on_refund: "maybe" as "keep" })), /on_refund/);
  assert.throws(() => splitPayout(feeTerms({ address: "M", bps: 10_000, on_refund: "keep" }), 5_000_000, "seller"), /cannot cover/);
});

test("ZIP 321 request for a two-output payout", () => {
  assert.equal(
    zip321Uri([{ to: "utest1a", amount_zat: 4_865_000, memo: "hi" }, { to: "utest1m", amount_zat: 125_000 }, { to: "utest1z", amount_zat: 100_000_000 }]),
    "zcash:?address=utest1a&amount=0.04865&memo=aGk&address.1=utest1m&amount.1=0.00125&address.2=utest1z&amount.2=1",
  );
});

test("signer expectation from a fee split: payee bounds + exact fee", () => {
  const pay = splitPayout(feeTerms({ address: "M", bps: 250, on_refund: "keep" }), 5_000_000, "seller");
  assert.deepEqual(expectFromPayments(pay, "memo"), {
    to: "S", min: 4_855_000, max: 4_875_000, memo: "memo", exact: [{ to: "M", zat: 125_000 }],
  });
  assert.deepEqual(expectFromPayments([{ to: "B", party: "buyer", min_amount_zat: 5 }]), { to: "B", min: 5, max: undefined, memo: undefined, exact: undefined });
  assert.throws(() => expectFromPayments([pay[0], { ...pay[1], max_amount_zat: 125_001 }]), /must be exact/);
});
