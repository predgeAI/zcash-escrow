// Marketplace mode: a deal state machine with fiat-denominated terms, paid out in stages from one
// shielded 2-of-3 FROST escrow.
//
// Shares of the deal's fiat value (default 9500 / 400 / 100 bps):
//   seller  paid to the seller once delivered (frozen by a negative review until it is updated)
//   reward  paid to the buyer for a verified review, before or after the seller is paid
//   fee     the marketplace's fee, collected once the seller has been paid; never kept on a refund
//
// Each payout is a *stage*: one transaction that spends the escrow notes, pays the stage's
// outputs and sends the remainder back to the escrow group's own internal address as change.
// A stage is described by a signed instruction (`predge.zescrow.verdict/3`, kind "stage") that
// binds the deal, the stage id, the state transition, the price quote, every payment, the
// network fee and the exact change. Signers re-derive the instruction from their own copy of
// the deal state and refuse anything else (`checkStage`), and a stage id signs only once.
//
// Events (delivered, reviews, disputes) are signed envelopes too: the marketplace operator signs
// ordinary events, only the arbiter can resolve a dispute. Every party folds the same signed
// event log and the executed stages into the same state (`replay`).
//
// The state machine is pure: no chain, no files. marketplace.ts runs it on a real escrow.

import { checkQuote, zatForFiat, type QuotePolicy, type SignedQuote } from "./pricelock.ts";
import { canonical, sha256, signCanonical, verifyCanonical, type ArbiterKey } from "./verdict.ts";

export const DEAL_SCHEMA = "predge.zescrow.deal/1";
export const EVENT_SCHEMA = "predge.zescrow.deal-event/1";
export const STAGE_SCHEMA = "predge.zescrow.verdict/3";
export const BPS = 10_000;

/** ZIP 317: 5,000 zat per logical action, at least 2 actions. */
export const zip317Fee = (actions: number) => 5_000 * Math.max(2, actions);
/** Network fee budget for the three ordinary stages (each at most 3 actions with one spend). */
export const DEFAULT_NETWORK_FEE_BUDGET_ZAT = 3 * zip317Fee(3);

export type ShareName = "seller" | "reward" | "fee";
export const SHARES: ShareName[] = ["seller", "reward", "fee"];

export interface Split {
  seller_bps: number;
  reward_bps: number;
  fee_bps: number;
}
export const DEFAULT_SPLIT: Split = { seller_bps: 9_500, reward_bps: 400, fee_bps: 100 };

/**
 * Fixed when the deal is created and committed to by the funding memo (terms hash). Payout
 * addresses of the buyer and the seller are not here: they are bound later, per stage.
 */
export interface DealTerms {
  schema: typeof DEAL_SCHEMA;
  deal_id: string;
  amount_usd_cents: number;
  split: Split;
  /** The marketplace's fee (revenue) address. */
  fee_address: string;
  /** The marketplace's PriceLock reserve: receives surplus, pays shortfalls. */
  reserve_address: string;
  escrow_address: string;
  /** The escrow's UFVK: signers accept change only to its internal scope. */
  escrow_ufvk: string;
  /** FROST group verifying key (Orchard/Ironwood `ak`), hex. */
  group_ak: string;
  operator_pubkey: string;
  arbiter_pubkey: string;
  quote_pubkey: string;
  quote_max_age_s: number;
  price_tolerance_bps: number;
  network_fee_budget_zat: number;
  /**
   * Optional Ed25519 keys of the buyer's and seller's marketplace accounts. When a party has one,
   * a payout address for it must carry that key's signature, not only the operator's attestation.
   */
  party_keys?: { buyer?: string; seller?: string };
}

export type Sentiment = "positive" | "negative";

export type DealEvent =
  /** `paid_at`: when the buyer sent the deposit, computed from `quote`, which must be fresh then. */
  | { type: "funded"; funded_zat: number; quote: SignedQuote; paid_at: string; fund_txid?: string }
  | { type: "delivered" }
  | { type: "review"; sentiment: Sentiment }
  | { type: "review_updated"; sentiment: Sentiment }
  | { type: "dispute_opened"; by: "buyer" | "seller" | "operator"; reason: string }
  | { type: "dispute_resolved"; decision: "release_seller" | "refund_buyer"; reasons: string[] };

export type Issuer = "operator" | "arbiter";

export interface EventEnvelope {
  schema: typeof EVENT_SCHEMA;
  deal_id: string;
  seq: number;
  at: string;
  event: DealEvent;
  issuer: Issuer;
  issuer_pubkey: string;
}
export interface SignedEvent {
  envelope: EventEnvelope;
  signature: string;
}

/** locked: not yet due; payable: may be paid now; frozen: held by a negative review. */
export type ShareState = "locked" | "payable" | "frozen" | "paid" | "refunded" | "waived";

export type StageKind = "seller_payout" | "reward_payout" | "fee_payout" | "refund";
const TRANSITION: Record<StageKind, string> = {
  seller_payout: "seller_paid", reward_payout: "reward_claimed", fee_payout: "fee_collected", refund: "refunded",
};

export interface DealState {
  terms: DealTerms;
  terms_sha256: string;
  status: "created" | "funded" | "closed";
  delivered: boolean;
  disputed: boolean;
  /** Set by an arbiter's refund decision: the next stage must be the refund. */
  refund_due: boolean;
  review: "none" | Sentiment;
  shares: Record<ShareName, ShareState>;
  fiat_cents: Record<ShareName, number>;
  tranche_zat: Record<ShareName, number>;
  funding_quote?: SignedQuote;
  principal_zat: number;
  funded_zat: number;
  /** What the escrow holds after the executed stages (deposit, then each stage's change). */
  escrow_zat: number;
  event_seq: number;
  next_stage_seq: number;
  executed: string[];
  log: string[];
}

export class IllegalTransition extends Error {}
const illegal = (m: string): never => { throw new IllegalTransition(m); };

/** A quote the deal cannot use is an illegal transition like any other. */
function quoteOk(q: SignedQuote, t: DealTerms, at: Date, reference?: number) {
  try {
    return checkQuote(q, quotePolicy(t), at, reference);
  } catch (e) {
    return illegal((e as Error).message);
  }
}

const isInt = (n: unknown, min = 0): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= min;

export function validateTerms(t: DealTerms): void {
  if (t.schema !== DEAL_SCHEMA) throw new Error("not a deal/1 terms object");
  if (!t.deal_id || /[^A-Za-z0-9_.-]/.test(t.deal_id)) throw new Error("deal_id must be [A-Za-z0-9_.-]+");
  if (!isInt(t.amount_usd_cents, 1)) throw new Error("amount_usd_cents must be a positive integer");
  const { seller_bps, reward_bps, fee_bps } = t.split;
  if (![seller_bps, reward_bps, fee_bps].every((b) => isInt(b)) || seller_bps + reward_bps + fee_bps !== BPS)
    throw new Error("split must be three non-negative integers summing to 10000 bps");
  if (seller_bps === 0) throw new Error("the seller share cannot be zero");
  if (!t.fee_address || !t.reserve_address || t.fee_address === t.reserve_address)
    throw new Error("fee_address and reserve_address are required and must differ");
  for (const k of ["escrow_address", "escrow_ufvk", "group_ak", "operator_pubkey", "arbiter_pubkey", "quote_pubkey"] as const)
    if (!t[k]) throw new Error(`${k} is required`);
  if (t.operator_pubkey === t.arbiter_pubkey) throw new Error("operator and arbiter must use different keys");
  if (!isInt(t.quote_max_age_s, 1) || !isInt(t.price_tolerance_bps)) throw new Error("bad quote policy");
  if (!isInt(t.network_fee_budget_zat)) throw new Error("bad network fee budget");
}

export const quotePolicy = (t: DealTerms): QuotePolicy =>
  ({ quote_pubkey: t.quote_pubkey, quote_max_age_s: t.quote_max_age_s, price_tolerance_bps: t.price_tolerance_bps });

/** Split an integer total by the deal's bps: seller and reward rounded down, the fee takes the rest. */
export function splitAmount(total: number, s: Split): Record<ShareName, number> {
  const seller = Number((BigInt(total) * BigInt(s.seller_bps)) / BigInt(BPS));
  const reward = Number((BigInt(total) * BigInt(s.reward_bps)) / BigInt(BPS));
  return { seller, reward, fee: total - seller - reward };
}

export function newDeal(terms: DealTerms): DealState {
  validateTerms(terms);
  return {
    terms, terms_sha256: sha256(canonical(terms)), status: "created", delivered: false, disputed: false, refund_due: false,
    review: "none", shares: { seller: "locked", reward: "locked", fee: "locked" },
    fiat_cents: splitAmount(terms.amount_usd_cents, terms.split), tranche_zat: { seller: 0, reward: 0, fee: 0 },
    principal_zat: 0, funded_zat: 0, escrow_zat: 0, event_seq: 0, next_stage_seq: 1, executed: [], log: [],
  };
}

const clone = (s: DealState): DealState => JSON.parse(JSON.stringify(s)) as DealState;

// ---------- events ----------

export function signEvent(state: DealState, event: DealEvent, issuer: Issuer, key: ArbiterKey, at = new Date()): SignedEvent {
  const envelope: EventEnvelope = {
    schema: EVENT_SCHEMA, deal_id: state.terms.deal_id, seq: state.event_seq + 1, at: at.toISOString(), event, issuer,
    issuer_pubkey: key.pubHex,
  };
  return { envelope, signature: signCanonical(envelope, key) };
}

/** Funding needs principal (amount at the funding quote) plus the network fee budget. */
export function fundingZat(terms: DealTerms, quote: SignedQuote): number {
  return zatForFiat(terms.amount_usd_cents, quote.quote.price_micros) + terms.network_fee_budget_zat;
}

/** Apply one signed event. Throws IllegalTransition if the deal's rules do not allow it. */
export function applyEvent(state: DealState, se: SignedEvent): DealState {
  const e = se.envelope;
  const t = state.terms;
  if (e.schema !== EVENT_SCHEMA || e.deal_id !== t.deal_id) illegal("event is for another deal");
  const want = e.issuer === "operator" ? t.operator_pubkey : e.issuer === "arbiter" ? t.arbiter_pubkey : illegal("unknown issuer");
  if (e.issuer_pubkey !== want || !verifyCanonical(e, se.signature, want)) illegal(`event signature is not the ${e.issuer}'s`);
  if (e.seq !== state.event_seq + 1) illegal(`event seq ${e.seq} replayed or out of order (expected ${state.event_seq + 1})`);
  const s = clone(state);
  s.event_seq = e.seq;
  const ev = e.event;
  if (ev.type !== "dispute_resolved" && e.issuer !== "operator") illegal(`${ev.type} must be issued by the operator`);
  if (s.status === "closed") illegal(`deal is closed; ${ev.type} not allowed`);
  switch (ev.type) {
    case "funded": {
      if (s.status !== "created") illegal("deal is already funded");
      // The deposit was computed from the quote when the buyer paid; confirmations take longer
      // than a quote lives, so freshness is judged at payment time, which cannot be after the event.
      const paid = Date.parse(ev.paid_at);
      if (!Number.isFinite(paid) || paid > Date.parse(e.at) + 60_000) illegal("funding paid_at is missing or after the event");
      quoteOk(ev.quote, t, new Date(paid));
      const principal = zatForFiat(t.amount_usd_cents, ev.quote.quote.price_micros);
      if (ev.funded_zat !== principal + t.network_fee_budget_zat)
        illegal(`escrow funded with ${ev.funded_zat} zat, expected ${principal + t.network_fee_budget_zat} (principal ${principal} + network fee budget ${t.network_fee_budget_zat})`);
      s.status = "funded";
      s.funding_quote = ev.quote;
      s.principal_zat = principal;
      s.funded_zat = ev.funded_zat;
      s.escrow_zat = ev.funded_zat;
      s.tranche_zat = splitAmount(principal, t.split);
      break;
    }
    case "delivered":
      if (s.status !== "funded") illegal("delivery before funding");
      if (s.delivered) illegal("already delivered");
      if (s.disputed) illegal("dispute open: delivery is decided by the arbiter");
      if (s.refund_due || s.shares.seller === "refunded") illegal("deal is being refunded");
      s.delivered = true;
      if (s.shares.seller === "locked") s.shares.seller = "payable";
      break;
    case "review":
    case "review_updated": {
      if (!s.delivered) illegal("a verified review needs a delivered item");
      if (ev.type === "review" && s.review !== "none") illegal("already reviewed; use review_updated");
      if (ev.type === "review_updated" && s.review === "none") illegal("no review to update");
      s.review = ev.sentiment;
      // Any verified review, positive or negative, earns the buyer's reward.
      if (s.shares.reward === "locked") s.shares.reward = "payable";
      if (ev.sentiment === "negative") {
        // Freeze what has not been paid; an executed payout is never reversed.
        if (s.shares.seller === "payable" || s.shares.seller === "locked") s.shares.seller = "frozen";
      } else if (s.shares.seller === "frozen") {
        s.shares.seller = "payable";
      }
      break;
    }
    case "dispute_opened":
      if (s.status !== "funded") illegal("nothing to dispute before funding");
      if (s.disputed) illegal("dispute already open");
      if (SHARES.every((k) => settled(s.shares[k]))) illegal("nothing left in escrow to dispute");
      s.disputed = true;
      break;
    case "dispute_resolved":
      if (e.issuer !== "arbiter") illegal("only the arbiter resolves a dispute");
      if (!s.disputed) illegal("no dispute to resolve");
      s.disputed = false;
      if (ev.decision === "release_seller") {
        s.delivered = true;
        if (s.shares.seller === "frozen" || s.shares.seller === "locked") s.shares.seller = "payable";
      } else {
        s.refund_due = true;
      }
      break;
    default:
      illegal(`unknown event ${(ev as { type: string }).type}`);
  }
  s.log.push(`event ${e.seq} ${ev.type}${"sentiment" in ev ? ` ${ev.sentiment}` : ""}${"decision" in ev ? ` ${ev.decision}` : ""} by ${e.issuer}`);
  return s;
}

const settled = (x: ShareState) => x === "paid" || x === "refunded" || x === "waived";

// ---------- stages ----------

export type PaymentParty = "seller" | "buyer" | "marketplace_fee" | "reserve";

export interface StagePayment {
  to: string;
  party: PaymentParty;
  zat: number;
  /** obligation: the fiat obligation in ZEC; surplus: the rest of the tranche (and on the last stage the unused network fee budget) to the reserve. */
  purpose: "obligation" | "surplus";
}

/**
 * A payout address supplied when the stage is created (it can be unknown at funding). The
 * operator attests that it comes from the party's authenticated marketplace account; when the
 * terms register a key for the party, the party's own signature over {deal_id, party, address}
 * is required as well.
 */
export interface RecipientBinding {
  party: "buyer" | "seller" | "marketplace";
  address: string;
  attested_by: "operator";
  source: string;
  party_signature?: string;
}

export interface StageInstruction {
  schema: typeof STAGE_SCHEMA;
  kind: "stage";
  deal_id: string;
  terms_sha256: string;
  escrow_address: string;
  group_ak: string;
  stage_id: string;
  seq: number;
  stage: StageKind;
  transition: { event: string; shares: ShareName[]; from: Partial<Record<ShareName, ShareState>>; to: ShareState };
  /** Hash of the state the stage was planned from: a stage is valid only against that state. */
  state_sha256: string;
  fiat_usd_cents: number;
  quote: SignedQuote;
  /** fiat / price, and the ZEC set aside for these shares at funding. */
  due_zat: number;
  tranche_zat: number;
  recipient: RecipientBinding;
  payments: StagePayment[];
  /** ZEC fell: the marketplace pays this from its reserve, outside the escrow, so the recipient still gets the fiat value. */
  reserve_topup: { to: string; party: "seller" | "buyer"; zat: number } | null;
  escrow_before_zat: number;
  network_fee_zat: number;
  /** The remainder, back to the escrow group's own internal address. Null on the stage that empties the escrow. */
  change: { to: "escrow-internal"; zat: number } | null;
  /** Memo of the recipient's output: binds the transaction to this instruction. */
  memo: string;
  issuer: Issuer;
  issuer_pubkey: string;
  issued_at: string;
}

export interface SignedStage {
  instruction: StageInstruction;
  signature: string;
}

/** The parts of the state a stage is planned from (not the log). */
export function stateHash(s: DealState): string {
  const { log: _log, ...rest } = s;
  return sha256(canonical(rest));
}

export function addressMessage(dealId: string, party: string, address: string) {
  return { schema: "predge.zescrow.payout-address/1", deal_id: dealId, party, address };
}

function checkBinding(s: DealState, b: RecipientBinding, party: RecipientBinding["party"]) {
  if (b.party !== party) illegal(`stage pays the ${party}, but the address is bound for the ${b.party}`);
  if (!b.address) illegal("no payout address");
  if (b.attested_by !== "operator" || !b.source) illegal("payout address carries no operator attestation");
  const t = s.terms;
  if (b.address === t.escrow_address) illegal("payout address is the escrow itself");
  if (party !== "marketplace" && (b.address === t.fee_address || b.address === t.reserve_address))
    illegal(`the ${party}'s payout address is a marketplace address`);
  const pk = party === "marketplace" ? undefined : t.party_keys?.[party];
  if (pk && !(b.party_signature && verifyCanonical(addressMessage(t.deal_id, party, b.address), b.party_signature, pk)))
    illegal(`the ${party}'s payout address is not signed by the ${party}'s registered key`);
}

export interface StageRequest {
  stage: StageKind;
  quote: SignedQuote;
  /** Required for seller, reward and refund stages; the fee stage pays the terms' fee address. */
  recipient?: RecipientBinding;
  issuer?: Issuer;
  issuer_pubkey?: string;
  at?: Date;
}

/**
 * Plan a stage from the current state: which shares it settles, the ZEC amounts at the quote,
 * the network fee and the change. Throws IllegalTransition if the rules do not allow it now.
 */
export function planStage(s: DealState, req: StageRequest): StageInstruction {
  const t = s.terms;
  const at = req.at ?? new Date();
  if (s.status === "created") illegal("escrow not funded");
  if (s.status === "closed") illegal("deal is closed: the escrow is empty");
  if (s.disputed) illegal("dispute open: nothing signs until the arbiter resolves it");
  if (s.refund_due && req.stage !== "refund") illegal("the arbiter decided a refund: only the refund stage may run");
  let shares: ShareName[];
  let party: RecipientBinding["party"];
  switch (req.stage) {
    case "seller_payout":
      if (s.shares.seller === "frozen") illegal("seller share is frozen by a negative review");
      if (s.shares.seller !== "payable") illegal(`seller share is ${s.shares.seller}`);
      shares = ["seller"]; party = "seller";
      break;
    case "reward_payout":
      if (s.shares.reward !== "payable") illegal(s.shares.reward === "locked" ? "no verified review yet: reward not claimable" : `reward is ${s.shares.reward}`);
      shares = ["reward"]; party = "buyer";
      break;
    case "fee_payout":
      if (s.shares.seller !== "paid") illegal("fee is collected only after the seller is paid");
      if (s.shares.fee !== "locked" && s.shares.fee !== "payable") illegal(`fee is ${s.shares.fee}`);
      shares = ["fee"]; party = "marketplace";
      break;
    case "refund":
      // Every share not yet paid goes back to the buyer, the marketplace fee included.
      shares = SHARES.filter((k) => !settled(s.shares[k]));
      if (shares.length === 0) illegal("nothing left to refund");
      if (s.shares.seller === "paid" && !s.refund_due) illegal("seller already paid: a refund needs an arbiter decision");
      party = "buyer";
      break;
    default:
      return illegal(`unknown stage ${(req.stage as string)}`);
  }
  const recipient: RecipientBinding = party === "marketplace"
    ? { party, address: t.fee_address, attested_by: "operator", source: "deal terms" }
    : req.recipient ?? illegal(`stage ${req.stage} needs the ${party}'s payout address`);
  checkBinding(s, recipient, party);
  quoteOk(req.quote, t, at);

  const fiat = shares.reduce((a, k) => a + s.fiat_cents[k], 0);
  const tranche = shares.reduce((a, k) => a + s.tranche_zat[k], 0);
  const due = zatForFiat(fiat, req.quote.quote.price_micros);
  const obligation = Math.min(due, tranche);
  const surplus = tranche - obligation;
  const shortfall = due - obligation;
  if (obligation <= 0) illegal("stage pays nothing");
  const final = SHARES.every((k) => shares.includes(k) || settled(s.shares[k]));
  const reserveParty: PaymentParty = "reserve";
  const payeeParty: PaymentParty = party === "marketplace" ? "marketplace_fee" : party;
  let reserve: number;
  let change: number;
  let fee: number;
  if (final) {
    // The last stage empties the escrow: unused network fee budget goes to the reserve with any
    // surplus. zcash-devtool's `pczt create` always adds a change output (here of zero value), so
    // the actions are the payments plus one.
    fee = zip317Fee(1 + 1 + 1);
    reserve = s.escrow_zat - obligation - fee;
    if (reserve <= 0) {
      fee = zip317Fee(1 + 1);
      reserve = s.escrow_zat - obligation - fee;
      if (reserve > 0) illegal(`the last ${reserve} zat cannot pay for their own output`);
    }
    change = 0;
  } else {
    reserve = surplus;
    fee = zip317Fee(1 + (reserve > 0 ? 1 : 0) + 1);
    change = s.escrow_zat - obligation - surplus - fee;
    if (change <= 0) illegal(`escrow of ${s.escrow_zat} zat cannot cover this stage and leave change`);
  }
  if (reserve < 0) illegal(`escrow of ${s.escrow_zat} zat cannot cover this stage`);
  const payments: StagePayment[] = [{ to: recipient.address, party: payeeParty, zat: obligation, purpose: "obligation" }];
  if (reserve > 0) payments.push({ to: t.reserve_address, party: reserveParty, zat: reserve, purpose: "surplus" });
  const seq = s.next_stage_seq;
  const stageId = `${t.deal_id}/${seq}-${req.stage}`;
  const body: Omit<StageInstruction, "memo" | "issuer" | "issuer_pubkey" | "issued_at"> = {
    schema: STAGE_SCHEMA, kind: "stage", deal_id: t.deal_id, terms_sha256: s.terms_sha256, escrow_address: t.escrow_address,
    group_ak: t.group_ak, stage_id: stageId, seq, stage: req.stage,
    transition: {
      event: TRANSITION[req.stage], shares, from: Object.fromEntries(shares.map((k) => [k, s.shares[k]])),
      to: req.stage === "refund" ? "refunded" : "paid",
    },
    state_sha256: stateHash(s), fiat_usd_cents: fiat, quote: req.quote, due_zat: due, tranche_zat: tranche, recipient, payments,
    // The marketplace's own fee has no top-up: it would be paying itself.
    reserve_topup: shortfall > 0 && party !== "marketplace" ? { to: recipient.address, party: party as "seller" | "buyer", zat: shortfall } : null,
    escrow_before_zat: s.escrow_zat, network_fee_zat: fee, change: change > 0 ? { to: "escrow-internal", zat: change } : null,
  };
  const issuer = req.issuer ?? "operator";
  return {
    ...body, memo: `zescrow stage ${sha256(canonical(body)).slice(0, 32)}`, issuer,
    issuer_pubkey: req.issuer_pubkey ?? (issuer === "operator" ? t.operator_pubkey : t.arbiter_pubkey), issued_at: at.toISOString(),
  };
}

export function signStage(ins: StageInstruction, key: ArbiterKey): SignedStage {
  if (ins.issuer_pubkey !== key.pubHex) throw new Error("instruction names a different issuer key");
  return { instruction: ins, signature: signCanonical(ins, key) };
}

/** What a signer hands `zescrow-frost sign-pczt` for a stage (see payout-check.ts Expect). */
export interface StageExpect {
  to: string;
  min: number;
  max: number;
  memo: string;
  exact?: { to: string; zat: number }[];
  change?: { ufvk: string; exact: number };
}

export interface CheckOptions {
  now?: Date;
  /** The signer's own ZEC/USD price (USD micros), e.g. its own median over exchanges. */
  reference_price_micros?: number;
  /** Stage ids this signer has already signed (its own one-shot ledger). */
  signed?: Iterable<string>;
}

/**
 * The signer's check of a stage instruction against its own copy of the deal state. Re-plans the
 * stage from that state, the instruction's quote and address binding, and requires the
 * instruction to be exactly that plan, signed by the issuer the terms name; the quote must be
 * fresh at `now` (and near the signer's reference price), and the stage id must be new.
 * Returns the PCZT policy for `zescrow-frost sign-pczt`.
 */
export function checkStage(s: DealState, ss: SignedStage, opts: CheckOptions = {}): StageExpect {
  const ins = ss.instruction;
  const t = s.terms;
  if (ins.schema !== STAGE_SCHEMA || ins.kind !== "stage") illegal("not a stage instruction");
  if (ins.deal_id !== t.deal_id || ins.terms_sha256 !== s.terms_sha256 || ins.escrow_address !== t.escrow_address || ins.group_ak !== t.group_ak)
    illegal("instruction is for another deal or escrow");
  const key = ins.issuer === "operator" ? t.operator_pubkey : ins.issuer === "arbiter" ? t.arbiter_pubkey : illegal("unknown issuer");
  if (ins.issuer_pubkey !== key || !verifyCanonical(ins, ss.signature, key)) illegal(`instruction signature is not the ${ins.issuer}'s`);
  const signed = new Set(opts.signed ?? []);
  if (s.executed.includes(ins.stage_id) || signed.has(ins.stage_id)) illegal(`stage ${ins.stage_id} already executed: replay refused`);
  if (ins.seq !== s.next_stage_seq) illegal(`stage seq ${ins.seq} is not the next stage (${s.next_stage_seq})`);
  const now = opts.now ?? new Date();
  quoteOk(ins.quote, t, now, opts.reference_price_micros);
  const plan = planStage(s, {
    stage: ins.stage, quote: ins.quote, recipient: ins.stage === "fee_payout" ? undefined : ins.recipient,
    issuer: ins.issuer, issuer_pubkey: ins.issuer_pubkey, at: new Date(ins.issued_at),
  });
  if (canonical(plan) !== canonical(ins)) illegal("instruction does not match the stage the deal state allows");
  return stageExpect(ins, t.escrow_ufvk);
}

export function stageExpect(ins: StageInstruction, escrowUfvk: string): StageExpect {
  const [main, ...rest] = ins.payments;
  return {
    to: main.to, min: main.zat, max: main.zat, memo: ins.memo,
    exact: rest.length ? rest.map((p) => ({ to: p.to, zat: p.zat })) : undefined,
    change: ins.change ? { ufvk: escrowUfvk, exact: ins.change.zat } : undefined,
  };
}

/** Record an executed stage (after its transaction is broadcast). A stage executes once. */
export function applyStage(s: DealState, ss: SignedStage): DealState {
  const ins = ss.instruction;
  if (s.executed.includes(ins.stage_id)) illegal(`stage ${ins.stage_id} already executed: replay refused`);
  if (ins.seq !== s.next_stage_seq || ins.state_sha256 !== stateHash(s)) illegal("stage was planned from another state");
  const n = clone(s);
  for (const k of ins.transition.shares) n.shares[k] = ins.transition.to;
  if (ins.stage === "refund") {
    if (n.shares.fee === "refunded") n.shares.fee = "waived";
    n.refund_due = false;
  }
  // The fee becomes collectable once the seller has been paid.
  if (n.shares.seller === "paid" && n.shares.fee === "locked") n.shares.fee = "payable";
  n.escrow_zat = ins.change?.zat ?? 0;
  n.executed.push(ins.stage_id);
  n.next_stage_seq += 1;
  if (SHARES.every((k) => settled(n.shares[k]))) {
    if (n.escrow_zat !== 0) illegal("deal settled but the escrow is not empty");
    n.status = "closed";
  }
  const paid = ins.payments.map((p) => `${p.party} ${p.zat}`).join(", ");
  n.log.push(`stage ${ins.stage_id}: ${ins.transition.event} (${paid} zat${ins.reserve_topup ? `; reserve tops up ${ins.reserve_topup.zat}` : ""}; change ${ins.change?.zat ?? 0})`);
  return n;
}

/** Every party's state: the same terms, signed event log and executed stages, folded in order. */
export function replay(terms: DealTerms, events: SignedEvent[], stages: { after_event: number; stage: SignedStage }[]): DealState {
  let s = newDeal(terms);
  const pending = [...stages].sort((a, b) => a.stage.instruction.seq - b.stage.instruction.seq);
  const flush = () => {
    while (pending.length && pending[0].after_event === s.event_seq) s = applyStage(s, pending.shift()!.stage);
  };
  flush();
  for (const e of events) {
    s = applyEvent(s, e);
    flush();
  }
  if (pending.length) illegal("stage log refers to events that are not in the event log");
  return s;
}
