# Changelog

## Unreleased

### Added

- Marketplace fee. Deal terms take an optional `marketplace_fee` (`bps` rounded down or
  `fixed_zat`, and `on_refund: keep | return`). The payout then has two outputs, the winner and
  the fee address, and no change. `zescrow-frost outputs` / `sign-pczt` take `--exact
  <address>:<zat>` (an exact payment) and `--max`, and run every existing check on the fee
  output too (commitment, ciphertext, ZIP 317 fee over all actions). A PCZT that drops or alters
  the fee is refused. Verdict schema `predge.zescrow.verdict/2` (`payments` list) for fee deals;
  `/1` is unchanged for deals without a fee. `scripts/zcash-devtool-payment-uri.patch` lets
  `pczt create` take a ZIP 321 request. Run on public testnet (path AF).

### Security

Three further signer-side gaps, reported by @danielgorgonha (DeegaLabs) in a review of the
previous fix. Thank you.

- The paying output's note ciphertext is now checked. `verify_note_commitment` binds the
  output's recipient and value to `cmx`, but not its `enc_ciphertext`, so a builder could keep
  the commitment honest and attach a ciphertext the payee cannot decrypt (the payee's wallet
  would never see the note), or any memo. For every output that carries value the signer now
  re-derives `esk` and `pk_d` from the commitment-verified note and opens the ciphertext with
  `zcash_note_encryption::try_output_recovery_with_pkd_esk`, in the domain of the output's pool
  (Orchard or Ironwood), and refuses if it does not open. When a memo is expected the payee's
  output must carry exactly it: on the verdict path, `zescrow verdict <verdict hash>`.
- The fee is now read and checked. The signer takes the fee from the Orchard and Ironwood
  bundles' value balance (the value the sighash commits to; transparent and Sapling parts are
  refused) and requires it to be exactly the ZIP 317 conventional fee
  (5,000 zat x max(2, actions)). A bundle may not carry more actions than one per real spend
  plus one per paying output (minimum 2), so padding cannot inflate the fee. Previously the fee
  was only bounded by the 20,000 zat allowance in the payout minimum.
- The signer reads the PCZT once. The new `zescrow-frost sign-pczt` reads the file a single
  time, runs every check above, derives the sighash from the same bytes with the `pczt` Signer
  role, refuses a signing package with any other message or a randomizer that is not one of the
  PCZT's spends, and only then produces the FROST share. The app no longer runs
  `zescrow-frost outputs` and `zcash-sign` separately on the same file for each signer.
  `zescrow-frost outputs` runs the same checks without signing.

### Tests and CI

- New Rust tests: undecryptable ciphertext refused, ciphertext replaced with another memo
  refused, wrong memo refused (including a real testnet PCZT with an empty memo), excess fee and
  padded actions refused, `sign-pczt` happy path and refusals. Real regtest, testnet and mainnet
  payout PCZTs (spend-side wallet metadata redacted) pass every check, and the sighash derived
  in Rust equals the one ZF `zcash-sign` prints for each.
- The npm tests against the `zescrow-frost` binary still skip locally when it is not built, now
  with a warning, and fail in CI (`CI=true`) instead of skipping.
- GitHub Actions workflow: builds the binary, runs `cargo fmt --check`, `cargo clippy`,
  `cargo test`, `npm run typecheck` and `npm test`.

### Security (earlier)

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
