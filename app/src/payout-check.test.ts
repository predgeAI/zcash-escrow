import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { payoutRefusal, verifiedOutputs, type VerifiedOutput } from "./payout-check.ts";
import { BIN, ROOT } from "./tools.ts";

const out = (value: number, to_expected: boolean, action = 0): VerifiedOutput =>
  ({ pool: "ironwood", action, value, receiver: "00", to_expected });

test("payout to the agreed receiver with a zero-value dummy is accepted", () => {
  assert.equal(payoutRefusal([out(0, false, 0), out(990, true, 1)], { min: 990 }), undefined);
});
test("underpayment, no outputs, or value to anyone else is refused", () => {
  assert.match(payoutRefusal([out(989, true)], { min: 990 })!, /pays 989 zat/);
  assert.match(payoutRefusal([], { min: 1 })!, /pays 0 zat/);
  assert.match(payoutRefusal([out(990, true), out(1, false, 1)], { min: 990 })!, /outputs to other addresses/);
});
test("an output without a valid value is refused, not skipped", () => {
  const bad = { ...out(0, false), value: undefined } as unknown as VerifiedOutput;
  assert.match(payoutRefusal([out(990, true, 1), bad], { min: 990 })!, /no valid value/);
});

// Against the real verifier (built with `cargo build --release` in crates/zescrow-frost).
const FIXTURE = join(ROOT, "crates/zescrow-frost/tests/fixtures/regtest-payout.proven.pczt");
const PAYEE = "uregtest1jfjdyhl4ac8q4qmgm3t3gws8n39axpp0x9vs2mnjwaa6eql6rxqd9uytf6mys68rlnx76kaghpp48g4kzrxeh0zq7q8qudyv9vd6t75v";
const skip = existsSync(BIN.frost) ? false : `zescrow-frost not built at ${BIN.frost}`;

test("zescrow-frost verifies the fixture's outputs against their commitments", { skip }, () => {
  const outs = verifiedOutputs(FIXTURE, PAYEE);
  assert.equal(outs.length, 2);
  assert.equal(payoutRefusal(outs, { min: 99_990_000 }), undefined);
});
test("zescrow-frost refuses a PCZT whose output value does not match its commitment", { skip }, () => {
  const bytes = readFileSync(FIXTURE);
  const at = bytes.indexOf(Buffer.from("01f0f3d62f", "hex")); // Some(99_990_000)
  assert.ok(at > 0);
  bytes[at + 1] = 0xf1; // Some(99_990_001), cmx unchanged
  const p = join(mkdtempSync(join(tmpdir(), "zpczt-")), "tampered.pczt");
  writeFileSync(p, bytes);
  assert.throws(() => verifiedOutputs(p, PAYEE), /does not open its note commitment/);
});
