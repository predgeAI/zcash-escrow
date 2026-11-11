# Contributing

Thanks for looking at zcash-escrow. Issues and pull requests are welcome.

## Reporting a problem

- Open a GitHub issue with what you ran, what you expected and what happened. Include the network (regtest or testnet), the commit, and the relevant log lines.
- Security problems (for example a way to make a signer contribute a share for a payment it did not agree to): please do not open a public issue. Email hello@predge.io first; we reply within 3 working days.

## Pull requests

1. Fork, create a branch from `main`, keep the change focused.
2. Rust: `cargo fmt` and `cargo clippy` clean, `cargo test` passes in `crates/zescrow-frost`.
3. App: `npm test` passes in `app/`.
4. If you touch the signer policy or the verdict format, add a test that shows the refusal case still holds.
5. Describe in the PR what you changed and how you checked it (regtest run, testnet txid, or test).

## Scope

The cryptography comes from ZF crates (reddsa, frost-rerandomized, frost-tools, zcash-sign). We do not add our own cryptographic primitives; changes there belong upstream.

## License

By contributing you agree that your contribution is licensed under the MIT License of this repository.
