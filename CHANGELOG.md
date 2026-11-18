# Changelog

## Unreleased

### Security

Two signer-side checks did not bind what they checked to what was signed. Neither was
exploitable in the current demo, where one process plays every role, but both would matter
once the builder, coordinator and signers are separate parties (milestone M1). Reported
privately by Daniel Gorgonha (DeegaLabs) against commit `1354fc7`. Thank you.

- FROST round 2 is now bound to the signer's own sighash. `zescrow-frost sign` takes a required
  `--expected-message` (the sighash the signer recomputed from the PCZT with `zcash-sign`) and
  refuses to produce a share if the coordinator's `SigningPackage` carries any other message.
  Previously the app compared the coordinator's sighash string, but the share was computed over
  whatever message the package contained.
- PCZT outputs are now verified against their note commitments. The new
  `zescrow-frost outputs` command opens every Orchard and Ironwood output (recipient, value,
  rseed, rho from the action's nullifier) against its `cmx` using the `pczt` and `orchard` crates
  on the same librustzcash revision zcash-devtool uses, and fails if any output cannot be opened,
  including an output with no value. Transparent and Sapling outputs are refused. The signer
  policy compares the committed Orchard receiver with the agreed address. Previously it parsed
  `zcash-devtool pczt inspect`, which shows the unauthenticated `user_address` label and silently
  skipped outputs without a value.
