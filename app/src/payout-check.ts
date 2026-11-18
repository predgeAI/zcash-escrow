// Signer-side payout check, done entirely by `zescrow-frost` from one read of the PCZT:
//   - every Orchard/Ironwood output opens against its note commitment (the `cmx` the sighash
//     covers); PCZT labels such as `user_address` are not used;
//   - every output that carries value has a note ciphertext that decrypts, so the payee's wallet
//     sees the note, and the payee's output carries the expected memo (e.g. the verdict hash);
//   - the fee is exactly the ZIP 317 conventional fee for the transaction's actions;
//   - at least `min` reaches the agreed address and nothing goes to anyone else;
//   - the sighash is derived from the same bytes.
// `checkPayout` runs those checks only; `signPayout` runs them and then produces this party's
// FROST share, refusing a signing package whose message is not that sighash.

import { frost } from "./tools.ts";

export interface VerifiedOutput {
  pool: string;
  action: number;
  value: number;
  /** Raw Orchard receiver, hex. */
  receiver: string;
  /** Whether the receiver is the Orchard receiver of the agreed address. */
  to_expected: boolean;
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
  /** Memo the payee's output must carry, when set. */
  memo?: string;
}

const policyArgs = (e: Expect) => [
  "--to", e.to, "--min", String(e.min), ...(e.memo !== undefined ? ["--memo", e.memo] : []),
];

/** Check `pczt` against `expect` without signing. Throws with the reason if any check fails. */
export function checkPayout(pczt: string, expect: Expect): PayoutCheck {
  return JSON.parse(frost(["outputs", "--pczt", pczt, ...policyArgs(expect)])) as PayoutCheck;
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
