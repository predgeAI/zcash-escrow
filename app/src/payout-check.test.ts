import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkPayout } from "./payout-check.ts";
import { BIN, ROOT } from "./tools.ts";

// These run against the real verifier (`cargo build --release` in crates/zescrow-frost).
// Locally they are skipped, loudly, when it is not built; in CI (CI=true) a missing binary fails.
const built = existsSync(BIN.frost);
const inCI = !!process.env.CI && process.env.CI !== "false";
const skip = built || inCI ? false : `zescrow-frost not built at ${BIN.frost} (cargo build --release)`;
if (skip) console.warn(`WARNING: skipping binary tests: ${skip}`);

const FIXTURES = join(ROOT, "crates/zescrow-frost/tests/fixtures");
const FIXTURE = join(FIXTURES, "regtest-payout.proven.pczt");
const PAYEE = "uregtest1jfjdyhl4ac8q4qmgm3t3gws8n39axpp0x9vs2mnjwaa6eql6rxqd9uytf6mys68rlnx76kaghpp48g4kzrxeh0zq7q8qudyv9vd6t75v";
const MEMO = "zescrow release A-mvvmoke4";
const PAID = 99_990_000;

const tampered = (patch: (b: Buffer) => void) => {
  const bytes = readFileSync(FIXTURE);
  patch(bytes);
  const p = join(mkdtempSync(join(tmpdir(), "zpczt-")), "tampered.pczt");
  writeFileSync(p, bytes);
  return p;
};

test("zescrow-frost binary is built", { skip }, () => {
  assert.ok(built, `zescrow-frost not found at ${BIN.frost}; build it with cargo build --release in crates/zescrow-frost`);
});
test("an honest payout passes: commitments, ciphertext, memo, ZIP 317 fee, sighash", { skip }, () => {
  const c = checkPayout(FIXTURE, { to: PAYEE, min: PAID, memo: MEMO });
  assert.equal(c.outputs.length, 2);
  assert.equal(c.fee, 10_000);
  assert.equal(c.sighash, "bbcb9c7afe04005fc867693a91a666f54331e0c067a7d15f48918d6ef68ffc30");
  assert.deepEqual(c.outputs.filter((o) => o.to_expected).map((o) => [o.value, o.memo]), [[PAID, MEMO]]);
});
test("a PCZT whose output value does not match its commitment is refused", { skip }, () => {
  const p = tampered((b) => {
    const at = b.indexOf(Buffer.from("01f0f3d62f", "hex")); // Some(99_990_000)
    assert.ok(at > 0);
    b[at + 1] = 0xf1; // Some(99_990_001), cmx unchanged
  });
  assert.throws(() => checkPayout(p, { to: PAYEE, min: 0 }), /does not open its note commitment/);
});
test("a payout memo without the expected verdict hash is refused", { skip }, () => {
  assert.throws(() => checkPayout(FIXTURE, { to: PAYEE, min: PAID, memo: "zescrow verdict 0123" }), /is not the expected memo/);
});
test("a fee above the ZIP 317 conventional fee is refused", { skip }, () => {
  const p = tampered((b) => {
    const at = b.indexOf(Buffer.from("904e00", "hex")); // Ironwood value_sum 10_000
    assert.ok(at > 0 && b.indexOf(Buffer.from("904e00", "hex"), at + 1) < 0);
    b[at] = 0x98; b[at + 1] = 0x75; // 15_000
  });
  assert.throws(() => checkPayout(p, { to: PAYEE, min: 0 }), /not the ZIP 317 conventional fee/);
});
test("underpayment is refused", { skip }, () => {
  assert.throws(() => checkPayout(FIXTURE, { to: PAYEE, min: PAID + 1 }), /pays 99990000 zat/);
});

// Marketplace fee: the two-output release from testnet run AF and the no-fee release refused there.
const FEE_RELEASE = join(FIXTURES, "testnet-fee-release.proven.pczt");
const FEE_MISSING = join(FIXTURES, "testnet-fee-missing.proven.pczt");
const SELLER = "utest197jhccyr9h55qx8603krk2ju9zvgnjstuj2uy0x9fsrm9jntdmxrdccl9syffa93d9csf7wew6czml70mryudvetjttza7vuusqckzuz";
const MARKETPLACE = "utest1dpdrfv009asg0yh0vjmw7wptx0lx8dz4zzhj5yn6z5kzw08yge6922npfswvm06gzl2t4fzds00dzj5pcexeunqdnadpfq5cz56ykxct";
const feeExpect = (zat: number, memo?: string) => ({ to: SELLER, min: 4_855_000, max: 4_875_000, memo, exact: [{ to: MARKETPLACE, zat }] });

test("a two-output fee payout passes: seller in bounds, fee exact, ZIP 317 fee for 3 actions", { skip }, () => {
  const c = checkPayout(FEE_RELEASE, feeExpect(125_000, "zescrow release AF-mwurzoyy"));
  assert.equal(c.fee, 15_000);
  assert.deepEqual(c.outputs.filter((o) => o.value > 0).map((o) => [o.value, o.to_expected, o.exact_payment]), [[4_860_000, true, null], [125_000, false, 0]]);
});
test("a payout without the fee output is refused", { skip }, () => {
  assert.throws(() => checkPayout(FEE_MISSING, feeExpect(125_000)), /pays 0 zat to the marketplace fee address, expected exactly 125000/);
});
test("a fee output with another amount is refused", { skip }, () => {
  assert.throws(() => checkPayout(FEE_RELEASE, feeExpect(124_999)), /pays 125000 zat to the marketplace fee address, expected exactly 124999/);
});
