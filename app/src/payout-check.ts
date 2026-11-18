// Signer-side output check. The outputs come from `zescrow-frost outputs`, which opens every
// Orchard/Ironwood output of the PCZT against its note commitment (the `cmx` the sighash covers)
// and fails if any output cannot be opened. PCZT labels such as `user_address` are not used.

import { frost } from "./tools.ts";

export interface VerifiedOutput {
  pool: string;
  action: number;
  value: number;
  /** Raw Orchard receiver, hex. */
  receiver: string;
  /** Whether the receiver is the Orchard receiver of the agreed address. */
  to_expected: boolean;
}

/** Every output of `pczt`, verified against its note commitment. Throws if any cannot be verified. */
export function verifiedOutputs(pczt: string, to: string): VerifiedOutput[] {
  return JSON.parse(frost(["outputs", "--pczt", pczt, "--to", to])) as VerifiedOutput[];
}

/** Why a signer must refuse these outputs, or undefined if they pay at least `min` to the agreed address and nothing to anyone else. */
export function payoutRefusal(outs: VerifiedOutput[], expect: { min: number }): string | undefined {
  for (const o of outs) {
    if (!Number.isSafeInteger(o.value) || o.value < 0) return `PCZT output ${o.pool} #${o.action} has no valid value`;
  }
  const paid = outs.filter((o) => o.to_expected).reduce((s, o) => s + o.value, 0);
  if (paid < expect.min) return `PCZT pays ${paid} zat to the agreed address, expected >= ${expect.min}`;
  if (outs.some((o) => !o.to_expected && o.value > 0)) return "PCZT has outputs to other addresses";
  return undefined;
}
