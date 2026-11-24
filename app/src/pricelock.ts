// PriceLock without holding fiat.
//
// The escrow stays in ZEC; the deal's obligations are in fiat (USD cents). Whenever a stage pays
// out, the ZEC amount is the fiat amount divided by the price in a signed quote:
//
//   zat = floor(usd_cents * 10^4 * 10^8 / price_micros)      (price_micros = USD 1e-6 per ZEC)
//
// A quote is canonical JSON signed with Ed25519 by a quote signer whose public key is fixed in
// the deal terms. Signers accept a quote only if its signature is valid, it is no older than the
// terms' `quote_max_age_s` (and not from the future beyond a small clock skew), its price is the
// median of the source prices it lists, and, when the signer has its own reference price, the
// quote is within `price_tolerance_bps` of it.
//
// For tests and testnet the quote signer is local (`localQuoteSigner`) and prices are set by
// hand. A real feed plugs in by replacing only the price source: a quote service fetches ZEC/USD
// from several exchanges (e.g. Kraken, Coinbase, Binance, Gemini), drops stale or missing ones,
// takes the median, and signs the same `predge.zescrow.quote/1` object with its key. Every
// signer can run the same fetch independently and pass its own median as `reference` to
// `checkQuote`, so one compromised quote key cannot move amounts by more than the tolerance.

import { ArbiterKey, loadArbiterKey, signCanonical, verifyCanonical } from "./verdict.ts";

export const QUOTE_SCHEMA = "predge.zescrow.quote/1";
/** Allowed clock skew for a quote dated in the future. */
export const QUOTE_SKEW_S = 60;

export interface PriceSource {
  name: string;
  price_micros: number;
}

export interface Quote {
  schema: typeof QUOTE_SCHEMA;
  pair: "ZEC/USD";
  /** USD per ZEC in micro-dollars (1e-6), e.g. 40_000_000 = $40.00. */
  price_micros: number;
  /** The prices the median was taken over. Empty only for a single hand-set test price. */
  sources: PriceSource[];
  method: "median";
  issued_at: string;
  signer_pubkey: string;
}

export interface SignedQuote {
  quote: Quote;
  signature: string;
}

const isPosInt = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n > 0;

/** Median of integer prices; for an even count, the floor of the mean of the two middle ones. */
export function median(prices: number[]): number {
  if (prices.length === 0) throw new Error("median of no prices");
  const s = [...prices].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : Math.floor((s[m - 1] + s[m]) / 2);
}

/** ZEC amount (zat) worth `usdCents` at `priceMicros` USD-micros per ZEC, rounded down. */
export function zatForFiat(usdCents: number, priceMicros: number): number {
  if (!Number.isSafeInteger(usdCents) || usdCents < 0) throw new Error("usd cents must be a non-negative integer");
  if (!isPosInt(priceMicros)) throw new Error("price must be a positive integer (USD micros per ZEC)");
  return Number((BigInt(usdCents) * 10_000n * 100_000_000n) / BigInt(priceMicros));
}

/** Sign a quote. `sources` defaults to the single given price (tests and testnet only). */
export function signQuote(key: ArbiterKey, priceMicros: number, at: Date, sources?: PriceSource[]): SignedQuote {
  const src = sources ?? [{ name: "local-test-price", price_micros: priceMicros }];
  const quote: Quote = {
    schema: QUOTE_SCHEMA, pair: "ZEC/USD", price_micros: priceMicros, sources: src, method: "median",
    issued_at: at.toISOString(), signer_pubkey: key.pubHex,
  };
  if (median(src.map((s) => s.price_micros)) !== priceMicros) throw new Error("quote price is not the median of its sources");
  return { quote, signature: signCanonical(quote, key) };
}

/** A local quote signer for tests and testnet: Ed25519 key on disk, prices set by the caller. */
export function localQuoteSigner(keyPath: string) {
  const key = loadArbiterKey(keyPath);
  return {
    pubHex: key.pubHex,
    /** Quote a hand-set price, e.g. `quote(40_000_000)` for $40.00. */
    quote: (priceMicros: number, at = new Date()) => signQuote(key, priceMicros, at),
    /** The shape a real feed produces: the median over several exchanges' prices. */
    quoteMedian: (sources: PriceSource[], at = new Date()) => signQuote(key, median(sources.map((s) => s.price_micros)), at, sources),
  };
}

export interface QuotePolicy {
  quote_pubkey: string;
  quote_max_age_s: number;
  price_tolerance_bps: number;
}

/**
 * Check a quote at time `now`. Throws with the reason. `reference` is the checking signer's own
 * price (e.g. its own median over exchanges); when given, the quote must be within the tolerance.
 */
export function checkQuote(sq: SignedQuote, policy: QuotePolicy, now: Date, reference?: number): Quote {
  const q = sq.quote;
  if (q.schema !== QUOTE_SCHEMA || q.pair !== "ZEC/USD" || q.method !== "median") throw new Error("not a ZEC/USD median quote");
  if (q.signer_pubkey !== policy.quote_pubkey) throw new Error("quote is signed by a key the deal terms do not name");
  if (!verifyCanonical(q, sq.signature, q.signer_pubkey)) throw new Error("quote signature invalid");
  if (!isPosInt(q.price_micros)) throw new Error("quote price is not a positive integer");
  if (!Array.isArray(q.sources) || q.sources.length === 0 || !q.sources.every((s) => isPosInt(s.price_micros)))
    throw new Error("quote lists no valid source prices");
  if (median(q.sources.map((s) => s.price_micros)) !== q.price_micros) throw new Error("quote price is not the median of its sources");
  const t = Date.parse(q.issued_at);
  if (!Number.isFinite(t)) throw new Error("quote has no valid issued_at");
  const age = (now.getTime() - t) / 1000;
  if (age > policy.quote_max_age_s) throw new Error(`quote is ${Math.round(age)} s old, older than the ${policy.quote_max_age_s} s allowed`);
  if (age < -QUOTE_SKEW_S) throw new Error("quote is dated in the future");
  if (reference !== undefined) {
    if (!isPosInt(reference)) throw new Error("reference price must be a positive integer");
    const diffBps = (Math.abs(q.price_micros - reference) * 10_000) / reference;
    if (diffBps > policy.price_tolerance_bps)
      throw new Error(`quote price ${q.price_micros} is ${diffBps.toFixed(1)} bps from the signer's reference ${reference}, more than ${policy.price_tolerance_bps} bps`);
  }
  return q;
}
