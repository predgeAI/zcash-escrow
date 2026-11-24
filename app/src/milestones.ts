// Milestone orders: a fiat-denominated order paid to one seller in milestones (by default 25% when
// a preview is delivered, 75% when the client accepts the final work), from one shielded 2-of-3
// FROST escrow. Built for ZEC Order Pay's order flow; the same rules as marketplace mode (deal.ts):
//
//   - the order terms fix the fiat amount, the milestone split, the seller's payout address, the
//     client's refund address, and the keys allowed to sign events, instructions and quotes;
//   - every milestone is a stage: one transaction that pays the milestone and returns the rest to
//     the escrow group's own internal address (`--change-to-group`);
//   - a stage is a signed instruction (`predge.zescrow.verdict/3`, kind "stage") that every signer
//     re-derives from its own replica of the signed event log, and signs once;
//   - a dispute stops every stage until the arbiter signs a resolution; a refund returns every
//     unpaid milestone to the client. A milestone that was paid is never reversed.
//
// Pure: no chain, no files. orderpay.ts runs it on a real escrow.

import { checkQuote, zatForFiat, type QuotePolicy, type SignedQuote } from "./pricelock.ts";
import { canonical, sha256, signCanonical, verifyCanonical, type ArbiterKey } from "./verdict.ts";
import { STAGE_SCHEMA, zip317Fee } from "./deal.ts";

export const ORDER_SCHEMA = "predge.zescrow.milestone-order/1";
export const ORDER_EVENT_SCHEMA = "predge.zescrow.order-event/1";
export const BPS = 10_000;

export type Milestone = "preview" | "acceptance";
export const MILESTONES: Milestone[] = ["preview", "acceptance"];

/** Two ordinary stages, each at most 3 actions with one spend. */
export const ORDER_NETWORK_FEE_BUDGET_ZAT = 2 * zip317Fee(3);

export interface OrderTerms {
  schema: typeof ORDER_SCHEMA;
  order_id: string;
  amount_usd_cents: number;
  /** Basis points of the order value per milestone; they sum to 10000. */
  split: Record<Milestone, number>;
  /** What each milestone event means, in the parties' words. */
  definitions: Record<Milestone, string>;
  /** The seller's payout address, given by the seller in writing before funding. */
  seller_address: string;
  /** Where a refund goes (the client's address). */
  buyer_refund_address: string;
  /** PriceLock reserve: receives surplus and the unused network fee budget, owes shortfalls. */
  reserve_address: string;
  escrow_address: string;
  escrow_ufvk: string;
  group_ak: string;
  operator_pubkey: string;
  arbiter_pubkey: string;
  quote_pubkey: string;
  quote_max_age_s: number;
  price_tolerance_bps: number;
  network_fee_budget_zat: number;
}

export type OrderEvent =
  | { type: "funded"; funded_zat: number; quote: SignedQuote; paid_at: string; fund_txid?: string }
  /** The seller sent the client a working preview link (`evidence_sha256` of the link and message). */
  | { type: "preview_delivered"; evidence_sha256: string; note: string }
  /** The client confirmed in writing that the final work matches the spec. */
  | { type: "accepted"; evidence_sha256: string; note: string }
  | { type: "dispute_opened"; by: "buyer" | "seller"; reason: string }
  | { type: "dispute_resolved"; decision: "release_seller" | "refund_buyer"; reasons: string[] };

export type Issuer = "operator" | "arbiter";

export interface OrderEnvelope {
  schema: typeof ORDER_EVENT_SCHEMA;
  order_id: string;
  seq: number;
  at: string;
  event: OrderEvent;
  issuer: Issuer;
  issuer_pubkey: string;
}
export interface SignedOrderEvent {
  envelope: OrderEnvelope;
  signature: string;
}

export type MilestoneState = "locked" | "payable" | "paid" | "refunded";
export type OrderStageKind = "preview_payout" | "acceptance_payout" | "refund";
const STAGE_MILESTONE: Record<"preview_payout" | "acceptance_payout", Milestone> = { preview_payout: "preview", acceptance_payout: "acceptance" };
const TRANSITION: Record<OrderStageKind, string> = { preview_payout: "preview_paid", acceptance_payout: "acceptance_paid", refund: "refunded" };

export interface OrderState {
  terms: OrderTerms;
  terms_sha256: string;
  status: "created" | "funded" | "closed";
  preview_delivered: boolean;
  accepted: boolean;
  disputed: boolean;
  refund_due: boolean;
  shares: Record<Milestone, MilestoneState>;
  fiat_cents: Record<Milestone, number>;
  tranche_zat: Record<Milestone, number>;
  principal_zat: number;
  funded_zat: number;
  escrow_zat: number;
  event_seq: number;
  next_stage_seq: number;
  executed: string[];
  log: string[];
}

export class IllegalTransition extends Error {}
const illegal = (m: string): never => { throw new IllegalTransition(m); };
const isInt = (n: unknown, min = 0): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= min;
const settled = (x: MilestoneState) => x === "paid" || x === "refunded";
const clone = <T>(s: T): T => JSON.parse(JSON.stringify(s)) as T;

export const quotePolicy = (t: OrderTerms): QuotePolicy =>
  ({ quote_pubkey: t.quote_pubkey, quote_max_age_s: t.quote_max_age_s, price_tolerance_bps: t.price_tolerance_bps });

function quoteOk(q: SignedQuote, t: OrderTerms, at: Date, reference?: number) {
  try { return checkQuote(q, quotePolicy(t), at, reference); } catch (e) { return illegal((e as Error).message); }
}

export function validateOrderTerms(t: OrderTerms): void {
  if (t.schema !== ORDER_SCHEMA) throw new Error("not a milestone-order/1 terms object");
  if (!t.order_id || /[^A-Za-z0-9_.-]/.test(t.order_id)) throw new Error("order_id must be [A-Za-z0-9_.-]+");
  if (!isInt(t.amount_usd_cents, 1)) throw new Error("amount_usd_cents must be a positive integer");
  if (!MILESTONES.every((m) => isInt(t.split[m], 1)) || MILESTONES.reduce((a, m) => a + t.split[m], 0) !== BPS)
    throw new Error("split must be positive integers summing to 10000 bps");
  const addrs = [t.seller_address, t.buyer_refund_address, t.reserve_address, t.escrow_address];
  if (addrs.some((a) => !a) || new Set(addrs).size !== addrs.length) throw new Error("seller, refund, reserve and escrow addresses are required and must differ");
  for (const k of ["escrow_ufvk", "group_ak", "operator_pubkey", "arbiter_pubkey", "quote_pubkey"] as const) if (!t[k]) throw new Error(`${k} is required`);
  if (t.operator_pubkey === t.arbiter_pubkey) throw new Error("operator and arbiter must use different keys");
  if (!isInt(t.quote_max_age_s, 1) || !isInt(t.price_tolerance_bps) || !isInt(t.network_fee_budget_zat)) throw new Error("bad quote policy or fee budget");
}

/** Split an integer total by the milestone bps: the preview rounded down, acceptance takes the rest. */
export function splitOrder(total: number, split: Record<Milestone, number>): Record<Milestone, number> {
  const preview = Number((BigInt(total) * BigInt(split.preview)) / BigInt(BPS));
  return { preview, acceptance: total - preview };
}

export function newOrder(terms: OrderTerms): OrderState {
  validateOrderTerms(terms);
  return {
    terms, terms_sha256: sha256(canonical(terms)), status: "created", preview_delivered: false, accepted: false, disputed: false,
    refund_due: false, shares: { preview: "locked", acceptance: "locked" }, fiat_cents: splitOrder(terms.amount_usd_cents, terms.split),
    tranche_zat: { preview: 0, acceptance: 0 }, principal_zat: 0, funded_zat: 0, escrow_zat: 0, event_seq: 0, next_stage_seq: 1,
    executed: [], log: [],
  };
}

export const orderFundingZat = (t: OrderTerms, q: SignedQuote) => zatForFiat(t.amount_usd_cents, q.quote.price_micros) + t.network_fee_budget_zat;

// ---------- events ----------

export function signOrderEvent(state: OrderState, event: OrderEvent, issuer: Issuer, key: ArbiterKey, at = new Date()): SignedOrderEvent {
  const envelope: OrderEnvelope = {
    schema: ORDER_EVENT_SCHEMA, order_id: state.terms.order_id, seq: state.event_seq + 1, at: at.toISOString(), event, issuer, issuer_pubkey: key.pubHex,
  };
  return { envelope, signature: signCanonical(envelope, key) };
}

export function applyOrderEvent(state: OrderState, se: SignedOrderEvent): OrderState {
  const e = se.envelope;
  const t = state.terms;
  if (e.schema !== ORDER_EVENT_SCHEMA || e.order_id !== t.order_id) illegal("event is for another order");
  const want = e.issuer === "operator" ? t.operator_pubkey : e.issuer === "arbiter" ? t.arbiter_pubkey : illegal("unknown issuer");
  if (e.issuer_pubkey !== want || !verifyCanonical(e, se.signature, want)) illegal(`event signature is not the ${e.issuer}'s`);
  if (e.seq !== state.event_seq + 1) illegal(`event seq ${e.seq} replayed or out of order (expected ${state.event_seq + 1})`);
  const s = clone(state);
  s.event_seq = e.seq;
  const ev = e.event;
  if (ev.type !== "dispute_resolved" && e.issuer !== "operator") illegal(`${ev.type} must be issued by the operator`);
  if (s.status === "closed") illegal(`order is closed; ${ev.type} not allowed`);
  const open = () => {
    if (s.status !== "funded") illegal(`${ev.type} before funding`);
    if (s.disputed) illegal(`dispute open: ${ev.type} is decided by the arbiter`);
    if (s.refund_due || MILESTONES.some((m) => s.shares[m] === "refunded")) illegal("order is being refunded");
  };
  switch (ev.type) {
    case "funded": {
      if (s.status !== "created") illegal("order is already funded");
      const paid = Date.parse(ev.paid_at);
      if (!Number.isFinite(paid) || paid > Date.parse(e.at) + 60_000) illegal("funding paid_at is missing or after the event");
      quoteOk(ev.quote, t, new Date(paid));
      const principal = zatForFiat(t.amount_usd_cents, ev.quote.quote.price_micros);
      if (ev.funded_zat !== principal + t.network_fee_budget_zat)
        illegal(`escrow funded with ${ev.funded_zat} zat, expected ${principal + t.network_fee_budget_zat} (principal ${principal} + network fee budget ${t.network_fee_budget_zat})`);
      s.status = "funded";
      s.principal_zat = principal;
      s.funded_zat = s.escrow_zat = ev.funded_zat;
      s.tranche_zat = splitOrder(principal, t.split);
      break;
    }
    case "preview_delivered":
      open();
      if (s.preview_delivered) illegal("preview already delivered");
      if (!/^[0-9a-f]{64}$/.test(ev.evidence_sha256)) illegal("preview event needs an evidence hash");
      s.preview_delivered = true;
      if (s.shares.preview === "locked") s.shares.preview = "payable";
      break;
    case "accepted":
      open();
      if (!s.preview_delivered) illegal("acceptance before a preview was delivered");
      if (s.accepted) illegal("already accepted");
      if (!/^[0-9a-f]{64}$/.test(ev.evidence_sha256)) illegal("acceptance event needs an evidence hash");
      s.accepted = true;
      if (s.shares.acceptance === "locked") s.shares.acceptance = "payable";
      break;
    case "dispute_opened":
      if (s.status !== "funded") illegal("nothing to dispute before funding");
      if (s.disputed) illegal("dispute already open");
      if (MILESTONES.every((m) => settled(s.shares[m]))) illegal("nothing left in escrow to dispute");
      s.disputed = true;
      break;
    case "dispute_resolved":
      if (e.issuer !== "arbiter") illegal("only the arbiter resolves a dispute");
      if (!s.disputed) illegal("no dispute to resolve");
      s.disputed = false;
      if (ev.decision === "release_seller") {
        for (const m of MILESTONES) if (s.shares[m] === "locked") s.shares[m] = "payable";
      } else {
        s.refund_due = true;
      }
      break;
    default:
      illegal(`unknown event ${(ev as { type: string }).type}`);
  }
  s.log.push(`event ${e.seq} ${ev.type}${"decision" in ev ? ` ${ev.decision}` : ""} by ${e.issuer}`);
  return s;
}

// ---------- stages ----------

export interface OrderPayment {
  to: string;
  party: "seller" | "buyer" | "reserve";
  zat: number;
  purpose: "obligation" | "surplus";
}

export interface OrderStageInstruction {
  schema: typeof STAGE_SCHEMA;
  kind: "stage";
  order_schema: typeof ORDER_SCHEMA;
  deal_id: string;
  terms_sha256: string;
  escrow_address: string;
  group_ak: string;
  stage_id: string;
  seq: number;
  stage: OrderStageKind;
  transition: { event: string; shares: Milestone[]; from: Partial<Record<Milestone, MilestoneState>>; to: MilestoneState };
  state_sha256: string;
  fiat_usd_cents: number;
  quote: SignedQuote;
  due_zat: number;
  tranche_zat: number;
  recipient: { party: "seller" | "buyer"; address: string; source: "order terms" };
  payments: OrderPayment[];
  reserve_topup: { to: string; party: "seller" | "buyer"; zat: number } | null;
  escrow_before_zat: number;
  network_fee_zat: number;
  change: { to: "escrow-internal"; zat: number } | null;
  memo: string;
  issuer: Issuer;
  issuer_pubkey: string;
  issued_at: string;
}

export interface SignedOrderStage {
  instruction: OrderStageInstruction;
  signature: string;
}

export function orderStateHash(s: OrderState): string {
  const { log: _log, ...rest } = s;
  return sha256(canonical(rest));
}

export interface OrderStageRequest {
  stage: OrderStageKind;
  quote: SignedQuote;
  issuer?: Issuer;
  issuer_pubkey?: string;
  at?: Date;
}

export function planOrderStage(s: OrderState, req: OrderStageRequest): OrderStageInstruction {
  const t = s.terms;
  const at = req.at ?? new Date();
  if (s.status === "created") illegal("escrow not funded");
  if (s.status === "closed") illegal("order is closed: the escrow is empty");
  if (s.disputed) illegal("dispute open: nothing signs until the arbiter resolves it");
  if (s.refund_due && req.stage !== "refund") illegal("the arbiter decided a refund: only the refund stage may run");
  let shares: Milestone[];
  let party: "seller" | "buyer";
  if (req.stage === "refund") {
    shares = MILESTONES.filter((m) => !settled(s.shares[m]));
    if (shares.length === 0) illegal("nothing left to refund");
    if (!s.refund_due) illegal("a refund needs the arbiter's refund decision");
    party = "buyer";
  } else if (req.stage === "preview_payout" || req.stage === "acceptance_payout") {
    const m = STAGE_MILESTONE[req.stage];
    if (s.shares[m] !== "payable") illegal(`${m} milestone is ${s.shares[m]}`);
    shares = [m];
    party = "seller";
  } else return illegal(`unknown stage ${req.stage as string}`);
  const address = party === "seller" ? t.seller_address : t.buyer_refund_address;
  quoteOk(req.quote, t, at);

  const fiat = shares.reduce((a, m) => a + s.fiat_cents[m], 0);
  const tranche = shares.reduce((a, m) => a + s.tranche_zat[m], 0);
  const due = zatForFiat(fiat, req.quote.quote.price_micros);
  const obligation = Math.min(due, tranche);
  const surplus = tranche - obligation;
  const shortfall = due - obligation;
  if (obligation <= 0) illegal("stage pays nothing");
  const final = MILESTONES.every((m) => shares.includes(m) || settled(s.shares[m]));
  let reserve: number;
  let change: number;
  let fee: number;
  if (final) {
    // Empties the escrow: surplus and unused network fee budget to the reserve. zcash-devtool
    // always adds a (zero-value) change output, so the actions are the payments plus one.
    fee = zip317Fee(3);
    reserve = s.escrow_zat - obligation - fee;
    if (reserve <= 0) {
      fee = zip317Fee(2);
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
  const payments: OrderPayment[] = [{ to: address, party, zat: obligation, purpose: "obligation" }];
  if (reserve > 0) payments.push({ to: t.reserve_address, party: "reserve", zat: reserve, purpose: "surplus" });
  const seq = s.next_stage_seq;
  const body: Omit<OrderStageInstruction, "memo" | "issuer" | "issuer_pubkey" | "issued_at"> = {
    schema: STAGE_SCHEMA, kind: "stage", order_schema: ORDER_SCHEMA, deal_id: t.order_id, terms_sha256: s.terms_sha256,
    escrow_address: t.escrow_address, group_ak: t.group_ak, stage_id: `${t.order_id}/${seq}-${req.stage}`, seq, stage: req.stage,
    transition: { event: TRANSITION[req.stage], shares, from: Object.fromEntries(shares.map((m) => [m, s.shares[m]])), to: req.stage === "refund" ? "refunded" : "paid" },
    state_sha256: orderStateHash(s), fiat_usd_cents: fiat, quote: req.quote, due_zat: due, tranche_zat: tranche,
    recipient: { party, address, source: "order terms" }, payments,
    reserve_topup: shortfall > 0 ? { to: address, party, zat: shortfall } : null,
    escrow_before_zat: s.escrow_zat, network_fee_zat: fee, change: change > 0 ? { to: "escrow-internal", zat: change } : null,
  };
  const issuer = req.issuer ?? "operator";
  return {
    ...body, memo: `zescrow stage ${sha256(canonical(body)).slice(0, 32)}`, issuer,
    issuer_pubkey: req.issuer_pubkey ?? (issuer === "operator" ? t.operator_pubkey : t.arbiter_pubkey), issued_at: at.toISOString(),
  };
}

export function signOrderStage(ins: OrderStageInstruction, key: ArbiterKey): SignedOrderStage {
  if (ins.issuer_pubkey !== key.pubHex) throw new Error("instruction names a different issuer key");
  return { instruction: ins, signature: signCanonical(ins, key) };
}

export interface OrderStageExpect {
  to: string;
  min: number;
  max: number;
  memo: string;
  exact?: { to: string; zat: number }[];
  change?: { ufvk: string; exact: number };
}

/** A signer's check: re-plan from its own replica, compare exactly, verify the issuer, one shot per stage id. */
export function checkOrderStage(s: OrderState, ss: SignedOrderStage, opts: { now?: Date; reference_price_micros?: number; signed?: Iterable<string> } = {}): OrderStageExpect {
  const ins = ss.instruction;
  const t = s.terms;
  if (ins.schema !== STAGE_SCHEMA || ins.kind !== "stage" || ins.order_schema !== ORDER_SCHEMA) illegal("not an order stage instruction");
  if (ins.deal_id !== t.order_id || ins.terms_sha256 !== s.terms_sha256 || ins.escrow_address !== t.escrow_address || ins.group_ak !== t.group_ak)
    illegal("instruction is for another order or escrow");
  const key = ins.issuer === "operator" ? t.operator_pubkey : ins.issuer === "arbiter" ? t.arbiter_pubkey : illegal("unknown issuer");
  if (ins.issuer_pubkey !== key || !verifyCanonical(ins, ss.signature, key)) illegal(`instruction signature is not the ${ins.issuer}'s`);
  const signed = new Set(opts.signed ?? []);
  if (s.executed.includes(ins.stage_id) || signed.has(ins.stage_id)) illegal(`stage ${ins.stage_id} already executed: replay refused`);
  if (ins.seq !== s.next_stage_seq) illegal(`stage seq ${ins.seq} is not the next stage (${s.next_stage_seq})`);
  quoteOk(ins.quote, t, opts.now ?? new Date(), opts.reference_price_micros);
  const plan = planOrderStage(s, { stage: ins.stage, quote: ins.quote, issuer: ins.issuer, issuer_pubkey: ins.issuer_pubkey, at: new Date(ins.issued_at) });
  if (canonical(plan) !== canonical(ins)) illegal("instruction does not match the stage the order state allows");
  const [main, ...rest] = ins.payments;
  return {
    to: main.to, min: main.zat, max: main.zat, memo: ins.memo,
    exact: rest.length ? rest.map((p) => ({ to: p.to, zat: p.zat })) : undefined,
    change: ins.change ? { ufvk: t.escrow_ufvk, exact: ins.change.zat } : undefined,
  };
}

export function applyOrderStage(s: OrderState, ss: SignedOrderStage): OrderState {
  const ins = ss.instruction;
  if (s.executed.includes(ins.stage_id)) illegal(`stage ${ins.stage_id} already executed: replay refused`);
  if (ins.seq !== s.next_stage_seq || ins.state_sha256 !== orderStateHash(s)) illegal("stage was planned from another state");
  const n = clone(s);
  for (const m of ins.transition.shares) n.shares[m] = ins.transition.to;
  if (ins.stage === "refund") n.refund_due = false;
  n.escrow_zat = ins.change?.zat ?? 0;
  n.executed.push(ins.stage_id);
  n.next_stage_seq += 1;
  if (MILESTONES.every((m) => settled(n.shares[m]))) {
    if (n.escrow_zat !== 0) illegal("order settled but the escrow is not empty");
    n.status = "closed";
  }
  n.log.push(`stage ${ins.stage_id}: ${ins.transition.event} (${ins.payments.map((p) => `${p.party} ${p.zat}`).join(", ")} zat; change ${ins.change?.zat ?? 0})`);
  return n;
}

export function replayOrder(terms: OrderTerms, events: SignedOrderEvent[], stages: { after_event: number; stage: SignedOrderStage }[]): OrderState {
  let s = newOrder(terms);
  const pending = [...stages].sort((a, b) => a.stage.instruction.seq - b.stage.instruction.seq);
  const flush = () => { while (pending.length && pending[0].after_event === s.event_seq) s = applyOrderStage(s, pending.shift()!.stage); };
  flush();
  for (const e of events) { s = applyOrderEvent(s, e); flush(); }
  if (pending.length) illegal("stage log refers to events that are not in the event log");
  return s;
}
