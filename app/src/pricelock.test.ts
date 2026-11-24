import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkQuote, localQuoteSigner, median, signQuote, zatForFiat } from "./pricelock.ts";
import { loadArbiterKey } from "./verdict.ts";

const dir = mkdtempSync(join(tmpdir(), "zquote-"));
const signer = localQuoteSigner(join(dir, "q.pem"));
const policy = { quote_pubkey: signer.pubHex, quote_max_age_s: 300, price_tolerance_bps: 100 };
const now = new Date("2026-11-24T12:00:00Z");

test("fiat to zat at a price, rounded down", () => {
  assert.equal(zatForFiat(200, 40_000_000), 5_000_000);
  assert.equal(zatForFiat(190, 44_000_000), 4_318_181);
  assert.equal(zatForFiat(8, 38_000_000), 210_526);
  assert.equal(zatForFiat(0, 1), 0);
  assert.throws(() => zatForFiat(1, 0), /positive integer/);
  assert.throws(() => zatForFiat(1.5, 1), /integer/);
});

test("median over sources", () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2);
  assert.throws(() => median([]));
});

test("a fresh, signed median quote passes; stale, future, foreign-key, tampered or off-reference quotes do not", () => {
  const q = signer.quoteMedian([
    { name: "kraken", price_micros: 40_100_000 }, { name: "coinbase", price_micros: 39_900_000 }, { name: "binance", price_micros: 40_000_000 },
  ], now);
  assert.equal(checkQuote(q, policy, now).price_micros, 40_000_000);
  checkQuote(q, policy, now, 40_300_000);
  assert.throws(() => checkQuote(q, policy, now, 41_000_000), /bps from the signer's reference/);
  assert.throws(() => checkQuote(q, policy, new Date(now.getTime() + 301_000)), /older than/);
  assert.throws(() => checkQuote(q, policy, new Date(now.getTime() - 120_000)), /future/);
  const tampered = structuredClone(q);
  tampered.quote.price_micros = 30_000_000;
  tampered.quote.sources = [{ name: "x", price_micros: 30_000_000 }];
  assert.throws(() => checkQuote(tampered, policy, now), /signature invalid/);
  const other = signQuote(loadArbiterKey(join(dir, "other.pem")), 40_000_000, now);
  assert.throws(() => checkQuote(other, policy, now), /key the deal terms do not name/);
  assert.throws(() => signQuote(loadArbiterKey(join(dir, "q.pem")), 1, now, [{ name: "a", price_micros: 2 }]), /median/);
});
