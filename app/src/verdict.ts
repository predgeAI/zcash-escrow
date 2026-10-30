// Predge-style signed verdicts for the escrow arbiter.
//
// A verdict is canonical JSON (sorted keys, no whitespace) signed with Ed25519 (node:crypto).
// It names the decision, the reasons, the hash of every piece of evidence the arbiter
// looked at, and the exact payout (recipient + amount) the arbiter is willing to co-sign.
// The arbiter's FROST share is only ever used for a transaction whose outputs match it.

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

export interface Terms {
  item: string;
  price_zat: number;
  item_sha256: string; // seller commits to the deliverable's hash when listing
  deliver_by: string; // ISO time
  buyer_refund_address: string;
  seller_payout_address: string;
}

export interface Verdict {
  schema: "predge.zescrow.verdict/1";
  job_id: string;
  escrow_address: string;
  group_ak: string;
  terms_sha256: string;
  decision: Decision;
  reasons: string[];
  evidence: EvidenceItem[];
  payout: { to: string; party: "buyer" | "seller"; min_amount_zat: number };
  cosigner_with: "buyer" | "seller";
  issued_at: string;
  arbiter_pubkey: string; // raw Ed25519, hex
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
