// Predge-style signed verdicts for the escrow arbiter.
//
// A verdict is canonical JSON (sorted keys, no whitespace) signed with Ed25519 (node:crypto).
// It names the decision, the reasons, the hash of every piece of evidence the arbiter
// looked at, and the exact payout (recipient + amount) the arbiter is willing to co-sign.
// The arbiter's FROST share is only ever used for a transaction whose outputs match it.
//
// Two schema versions:
//   predge.zescrow.verdict/1  one recipient:     payout: { to, party, min_amount_zat }
//   predge.zescrow.verdict/2  list of payments:  payments: [{ to, party, min_amount_zat, max_amount_zat }]
// /2 is issued when the deal terms carry a marketplace fee (the payout then has two outputs:
// the winner and the marketplace's fee address). Deals without a fee keep issuing /1, and
// every reader accepts both (verdictPayments()).

import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, KeyObject } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type Decision = "release_to_seller" | "refund_buyer";

export interface EvidenceItem {
  party: "buyer" | "seller";
  kind: string; // e.g. "delivery", "complaint", "received_file"
  note: string;
  sha256: string; // hash of the submitted bytes; the bytes stay with the parties
  submitted_at: string;
}

/**
 * A marketplace's cut, fixed in the deal terms before the buyer funds the escrow (the funding
 * memo carries the terms hash). Exactly one of `bps` (basis points of `price_zat`, rounded down)
 * or `fixed_zat`. `on_refund`: "keep" = the marketplace keeps its fee when the buyer is refunded,
 * "return" = the buyer gets everything back.
 */
export interface MarketplaceFee {
  address: string;
  bps?: number;
  fixed_zat?: number;
  on_refund: "keep" | "return";
}

export interface Terms {
  item: string;
  price_zat: number;
  item_sha256: string; // seller commits to the deliverable's hash when listing
  deliver_by: string; // ISO time
  buyer_refund_address: string;
  seller_payout_address: string;
  marketplace_fee?: MarketplaceFee; // absent = no fee, single-output payouts as before
}

/** ZIP 317 network fee headroom for a payout: 2-3 logical actions x 5,000 zat today, with margin. */
export const FEE_ALLOWANCE_ZAT = 20_000;

export type PayeeParty = "buyer" | "seller" | "marketplace";

/**
 * One output the payout must contain. The PCZT must pay `to` between `min_amount_zat` and
 * `max_amount_zat` (inclusive; no upper bound if absent). The ZIP 317 network fee comes out of
 * the winner's output only, so a marketplace fee output has min == max (exact). The signers
 * enforce this in `zescrow-frost` (payout-check.ts, `expectFromPayments`).
 */
export interface Payment {
  to: string;
  party: PayeeParty;
  min_amount_zat: number;
  max_amount_zat?: number;
}

interface VerdictBase {
  job_id: string;
  escrow_address: string;
  group_ak: string;
  terms_sha256: string;
  decision: Decision;
  reasons: string[];
  evidence: EvidenceItem[];
  cosigner_with: "buyer" | "seller";
  issued_at: string;
  arbiter_pubkey: string; // raw Ed25519, hex
}

export interface VerdictV1 extends VerdictBase {
  schema: "predge.zescrow.verdict/1";
  payout: { to: string; party: "buyer" | "seller"; min_amount_zat: number };
}

export interface VerdictV2 extends VerdictBase {
  schema: "predge.zescrow.verdict/2";
  payments: Payment[];
}

export type Verdict = VerdictV1 | VerdictV2;

/** The payments a verdict authorizes, for either schema version. */
export function verdictPayments(v: Verdict): Payment[] {
  if (v.schema === "predge.zescrow.verdict/1") return [{ ...v.payout }];
  if (v.schema === "predge.zescrow.verdict/2") return v.payments.map((p) => ({ ...p }));
  throw new Error(`unknown verdict schema ${(v as { schema?: string }).schema}`);
}

/** The party the verdict pays out to (the winner), for either schema version. */
export function verdictWinner(v: Verdict): "buyer" | "seller" {
  return v.decision === "release_to_seller" ? "seller" : "buyer";
}

// ---------- marketplace fee ----------

/** Fee in zat from the terms: bps of price_zat rounded down, or fixed_zat. 0 if no fee. */
export function marketplaceFeeZat(terms: Terms): number {
  const f = terms.marketplace_fee;
  if (!f) return 0;
  validateMarketplaceFee(terms);
  if (f.bps !== undefined) return Number((BigInt(terms.price_zat) * BigInt(f.bps)) / 10_000n);
  return f.fixed_zat!;
}

export function validateMarketplaceFee(terms: Terms): void {
  const f = terms.marketplace_fee;
  if (!f) return;
  const isInt = (n: unknown) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
  if (!f.address) throw new Error("marketplace_fee.address is required");
  if ((f.bps === undefined) === (f.fixed_zat === undefined)) throw new Error("marketplace_fee needs exactly one of bps or fixed_zat");
  if (f.bps !== undefined && (!isInt(f.bps) || f.bps > 10_000)) throw new Error("marketplace_fee.bps must be an integer 0..10000");
  if (f.fixed_zat !== undefined && (!isInt(f.fixed_zat) || f.fixed_zat > terms.price_zat)) throw new Error("marketplace_fee.fixed_zat must be an integer 0..price_zat");
  if (f.on_refund !== "keep" && f.on_refund !== "return") throw new Error('marketplace_fee.on_refund must be "keep" or "return"');
  if (f.address === terms.buyer_refund_address || f.address === terms.seller_payout_address)
    throw new Error("marketplace_fee.address must differ from the buyer and seller addresses");
}

/**
 * The payments a payout to `winner` must make, from the deal terms and the escrowed amount.
 * Seller wins: the marketplace gets its fee, the seller gets the rest minus the network fee.
 * Buyer wins: same split if on_refund is "keep", the whole escrow (minus network fee) if "return".
 * Without a marketplace fee this is the single payment the app always made.
 */
export function splitPayout(terms: Terms, fundedZat: number, winner: "buyer" | "seller", feeAllowance = FEE_ALLOWANCE_ZAT): Payment[] {
  const fee = marketplaceFeeZat(terms);
  const takeFee = fee > 0 && (winner === "seller" || terms.marketplace_fee!.on_refund === "keep");
  const main = fundedZat - (takeFee ? fee : 0);
  if (main - feeAllowance <= 0) throw new Error(`escrow of ${fundedZat} zat cannot cover a ${fee} zat marketplace fee and the network fee`);
  const to = winner === "seller" ? terms.seller_payout_address : terms.buyer_refund_address;
  const payments: Payment[] = [{ to, party: winner, min_amount_zat: main - feeAllowance, max_amount_zat: main }];
  if (takeFee) payments.push({ to: terms.marketplace_fee!.address, party: "marketplace", min_amount_zat: fee, max_amount_zat: fee });
  return payments;
}

export interface SignedVerdict {
  verdict: Verdict;
  signature: string; // Ed25519 over canonical(verdict), hex
}

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

export const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

export interface ArbiterKey {
  priv: KeyObject;
  pub: KeyObject;
  pubHex: string;
}

/** Load or create the arbiter's Ed25519 verdict key (PKCS#8 PEM on disk). */
export function loadArbiterKey(path: string): ArbiterKey {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  }
  const priv = createPrivateKey(readFileSync(path));
  const pub = createPublicKey(priv);
  return { priv, pub, pubHex: rawPub(pub) };
}

function rawPub(pub: KeyObject): string {
  // SPKI DER for Ed25519 is a fixed 12-byte prefix followed by the 32-byte key.
  return (pub.export({ type: "spki", format: "der" }) as Buffer).subarray(12).toString("hex");
}

function pubFromRaw(hex: string): KeyObject {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function signVerdict(v: Verdict, key: ArbiterKey): SignedVerdict {
  if (v.arbiter_pubkey !== key.pubHex) throw new Error("verdict names a different arbiter key");
  return { verdict: v, signature: sign(null, Buffer.from(canonical(v)), key.priv).toString("hex") };
}

/** Anyone can check a verdict with only the JSON: no Zcash key, no network. */
export function verifyVerdict(sv: SignedVerdict, expectedArbiterPub?: string): boolean {
  if (expectedArbiterPub && sv.verdict.arbiter_pubkey !== expectedArbiterPub) return false;
  return verify(null, Buffer.from(canonical(sv.verdict)), pubFromRaw(sv.verdict.arbiter_pubkey), Buffer.from(sv.signature, "hex"));
}

/**
 * The adjudication rule for the demo (sealed-listing digital goods):
 * the seller committed to sha256(deliverable) in the terms. If the seller's evidence shows a
 * delivery whose hash matches that commitment, made on time, the seller is paid. Otherwise
 * the buyer is refunded. Real disputes plug Predge's evidence review in here; the signing
 * and co-signing path below does not change.
 */
export function adjudicate(terms: Terms, evidence: EvidenceItem[]): { decision: Decision; reasons: string[] } {
  const reasons: string[] = [];
  const deadline = Date.parse(terms.deliver_by);
  const deliveries = evidence.filter((e) => e.party === "seller" && e.kind === "delivery");
  const matching = deliveries.filter((e) => e.sha256 === terms.item_sha256);
  const onTime = matching.filter((e) => Date.parse(e.submitted_at) <= deadline);
  const buyerCopy = evidence.find((e) => e.party === "buyer" && e.kind === "received_file");

  if (deliveries.length === 0) reasons.push("seller submitted no delivery evidence");
  if (deliveries.length > 0 && matching.length === 0)
    reasons.push("no delivered file matches the item hash the seller committed to in the terms");
  if (matching.length > 0 && onTime.length === 0) reasons.push("matching delivery arrived after deliver_by");
  if (buyerCopy) {
    reasons.push(
      buyerCopy.sha256 === terms.item_sha256
        ? "the file the buyer says they received matches the committed item hash"
        : "the file the buyer says they received does not match the committed item hash",
    );
  }
  if (onTime.length > 0) {
    reasons.unshift("seller delivered, on time, a file matching the committed item hash");
    return { decision: "release_to_seller", reasons };
  }
  return { decision: "refund_buyer", reasons };
}
