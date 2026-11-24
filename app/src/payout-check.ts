// Signer-side payout check, done entirely by `zescrow-frost` from one read of the PCZT:
//   - every Orchard/Ironwood output opens against its note commitment (the `cmx` the sighash
//     covers); PCZT labels such as `user_address` are not used;
//   - every output that carries value has a note ciphertext that decrypts, so the payee's wallet
//     sees the note, and the payee's output carries the expected memo (e.g. the verdict hash);
//   - the fee is exactly the ZIP 317 conventional fee for the transaction's actions;
//   - at least `min` (and at most `max`) reaches the agreed address, each exact payment (a
//     marketplace fee) reaches its address exactly, and nothing goes to anyone else;
//   - the sighash is derived from the same bytes.
// `checkPayout` runs those checks only; `signPayout` runs them and then produces this party's
// FROST share, refusing a signing package whose message is not that sighash.

import { frost } from "./tools.ts";
import type { Payment } from "./verdict.ts";

export interface VerifiedOutput {
  pool: string;
  action: number;
  value: number;
  /** Raw Orchard receiver, hex. */
  receiver: string;
  /** Whether the receiver is the Orchard receiver of the agreed address. */
  to_expected: boolean;
  /** Index of the exact payment (e.g. marketplace fee) this output pays, if any. */
  exact_payment: number | null;
  /** Change back to the escrow group's own internal address (staged payouts). */
  to_group: boolean;
  /** The decrypted memo of an output that carries value (text, "" if empty, null if not text). */
  memo: string | null;
}

export interface PayoutCheck {
  outputs: VerifiedOutput[];
  /** Fee in zat, equal to the ZIP 317 conventional fee. */
  fee: number;
  actions: number;
  /** Shielded sighash, hex, derived from the checked PCZT. */
  sighash: string;
  /** `alpha` of every spend, hex. */
  alphas: string[];
}

/** What the signer requires of the payout. */
export interface Expect {
  /** Agreed payee (unified address). */
  to: string;
  /** Minimum the payee must receive, zat. */
  min: number;
  /** Maximum the payee may receive, zat (when set). */
  max?: number;
  /** Memo the payee's output must carry, when set. */
  memo?: string;
  /** Further payments that must be made exactly (a marketplace fee): address and zat. */
  exact?: { to: string; zat: number }[];
  /**
   * Staged payout: change back to the escrow group, only to the internal scope of `ufvk` (the
   * escrow's own UFVK, whose `ak` the signer checks against its FROST group key), exactly or at
   * least this much. Without it, any output back to the escrow is refused.
   */
  change?: { ufvk: string; exact?: number; min?: number };
}

const policyArgs = (e: Expect) => [
  "--to", e.to, "--min", String(e.min),
  ...(e.max !== undefined ? ["--max", String(e.max)] : []),
  ...(e.memo !== undefined ? ["--memo", e.memo] : []),
  ...(e.exact ?? []).flatMap((x) => ["--exact", `${x.to}:${x.zat}`]),
  ...(e.change ? ["--change-to-group", e.change.ufvk,
    ...(e.change.exact !== undefined ? ["--change-exact", String(e.change.exact)] : ["--change-min", String(e.change.min ?? 0)])] : []),
];

/**
 * The signer's expectation for a list of payments (verdictPayments / splitPayout): the first is
 * the payee (winner), which carries `memo` and absorbs the network fee; every other one must be
 * exact (min == max), e.g. the marketplace fee.
 */
export function expectFromPayments(payments: Payment[], memo?: string): Expect {
  const [main, ...rest] = payments;
  if (!main) throw new Error("no payments");
  for (const p of rest) {
    if (p.max_amount_zat !== p.min_amount_zat) throw new Error(`payment to ${p.party} must be exact`);
  }
  return {
    to: main.to, min: main.min_amount_zat, max: main.max_amount_zat, memo,
    exact: rest.length ? rest.map((p) => ({ to: p.to, zat: p.min_amount_zat })) : undefined,
  };
}

/** Check `pczt` against `expect` without signing. Throws with the reason if any check fails. */
export function checkPayout(pczt: string, expect: Expect, groupAk?: string): PayoutCheck {
  return JSON.parse(frost(["outputs", "--pczt", pczt, ...policyArgs(expect),
    ...(groupAk && expect.change ? ["--group-ak", groupAk] : [])])) as PayoutCheck;
}

/** Check `pczt` and produce this party's signature share over its sighash, from one read of the file. */
export function signPayout(
  pczt: string,
  expect: Expect,
  round: { key: string; nonces: string; package: string; randomizer: string; out: string },
): PayoutCheck {
  return JSON.parse(frost([
    "sign-pczt", "--pczt", pczt, ...policyArgs(expect), "--key", round.key, "--nonces", round.nonces,
    "--package", round.package, "--randomizer", round.randomizer, "--out", round.out,
  ])) as PayoutCheck;
}
