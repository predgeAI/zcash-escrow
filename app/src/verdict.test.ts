import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { adjudicate, loadArbiterKey, sha256, signVerdict, verifyVerdict, type Terms, type Verdict } from "./verdict.ts";

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
