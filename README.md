# Shielded 2-of-3 escrow for P2P commerce on Zcash

A buyer pays into a shielded address that nobody controls alone. The buyer, the seller and a
neutral arbiter each hold one FROST share of that address's spend key. Any two can pay out:

- **Deal goes fine:** buyer + seller sign, the seller is paid. The arbiter never hears about it.
- **Dispute:** both sides send evidence to the arbiter. The arbiter publishes a signed verdict
  and co-signs **only** the payout that verdict names, together with the winning party.
- **The arbiter cannot move funds by itself**, and it has no wallet and no seed. It holds one
  share out of three.

On chain this is an ordinary shielded transaction in the Ironwood pool. Nobody watching the
chain can tell it is an escrow, who the parties are, or that there was a dispute.

The arbiter in this repo is Predge. The protocol does not depend on that: the parties can
choose any arbiter that runs the same verdict-and-co-sign service.

Status: working MVP on a private regtest chain and on the public Zcash testnet (three payouts
and the arbiter's refusal, run on testnet on 31.10.2026). **Do not use with real funds.**

## What works today (verified by running it)

`npm run demo` runs three escrows end to end on a local Zebra 7.0.0 regtest chain. Each
payout below is a real v6 transaction, authorized by a 2-of-3 rerandomized FROST signature,
accepted by Zebra and mined.

| Path | Signers | Result in the last run (31.10.2026) |
|---|---|---|
| A. Release | buyer + seller | seller paid 0.9999 ZEC, tx `30fc8ff6…cbbb` |
| B. Dispute, nothing delivered | buyer + arbiter | buyer refunded 1.9999 ZEC, tx `214db34f…123d` |
| B'. Arbiter asked to pay the loser instead | arbiter alone checks | **refused**: "PCZT pays 0 zat to the agreed address" |
| C. Dispute, delivery proven | seller + arbiter | seller paid 2.9999 ZEC, tx `a8543ad2…31f5` |

The full run takes about 3.5 minutes on an M-series Mac. Proving takes about 3 s per payout.

**Public testnet, 31.10.2026** (`npm run testnet`, NU7, v6 Ironwood transactions via the
`zecrocks` lightwalletd). Same code, same 2-of-3 FROST signing; every transaction below is
mined on testnet:

| Path | Signers | Escrow | Funding tx (height) | Payout tx (height) |
|---|---|---|---|---|
| B. Dispute, nothing delivered | buyer + arbiter | 0.1 TAZ, buyer refunded 0.0999 | `9be35e8ee4e8ac867e29f7bd3929161fb1cc5b6043a29adafc5360a201ced80d` (4560069) | `2bc943804f1b30eb256a3f33b79a60677621c01e4cb41320ba7a32ee70c1f711` (4560131) |
| B'. Arbiter asked to pay the seller instead | arbiter alone checks | same escrow as B | (no tx) | **refused**: "PCZT pays 0 zat to the agreed address, expected >= 9980000" |
| A. Release | buyer + seller | 0.05 TAZ, seller paid 0.0499 | `b3287844c5f166ba93b2511c5827dc5feab8537fe7ddceca5639d6a517e3e807` (4560131) | `a22f6d89cb456f2613a077114f47ae220efae147aa3cbf7763ef647d365b40f9` (4560141) |
| C. Dispute, delivery proven | seller + arbiter | 0.05 TAZ, seller paid 0.0499 | `0ef86d4ef8450af48b15f9f0e10ea02b72ecf185da71f1c1e1e366781aeb5e19` (4560174) | `1e54334c4ee9afdd0c678548fdfc9da71a638b090377589ecd30eea39a5899d9` (4560212) |

Each escrow took about 15–25 minutes on testnet: the deposit needs 10 confirmations before the
view-only escrow wallet will spend it, and payouts waited from 1 to about 35 blocks to be mined.

| Part | Status |
|---|---|
| 2-of-3 key generation | **trusted dealer** (ZF `reddsa` `generate_with_dealer`). Each share is written to its party's directory and the dealer copy is deleted. DKG is milestone 1. |
| Escrow address and viewing key | ZF `zcash-sign generate` from the FROST group key. Funds land in **Ironwood**. |
| Funding | buyer's own `zcash-devtool` wallet, ordinary shielded send. |
| Payout | `zcash-devtool pczt create-max` → `pczt prove` → ZF `zcash-sign` (sighash + randomizer) → FROST rounds → `zcash-sign` applies the signature → `pczt send`. |
| Signer policy | before releasing a share, **every** signer re-derives the sighash from the PCZT with `zcash-sign`, and checks that the outputs pay the agreed address at least the agreed amount and nothing else. |
| Verdicts | Ed25519-signed canonical JSON: job id, decision, reasons, evidence hashes, exact payout. Anyone can check it offline (`zescrow verify`). The payout memo carries the verdict hash. |
| Adjudication | **stub rule** for sealed-listing digital goods (below). Real evidence review plugs in at `adjudicate()`. |
| Signer transport | **stub**: round messages are JSON files relayed by a local coordinator. Milestone 1 moves this to ZF `frostd`. |
| Network | regtest (`npm run demo`) and public testnet (`npm run testnet`, see "Testnet"). Testnet signing uses a locally patched `zcash-sign` build, because the pinned one does not know the NU7 branch id. |

## Run it

Requirements: Docker, rustup (rustc 1.90+), Node 20.

```bash
./scripts/build-deps.sh        # clones + builds pinned ZF frost-tools, zcash-devtool, this repo's crate
./scripts/chain-up.sh --reset  # Zebra 7.0.0 + Zaino 0.10.2 regtest, NU5..NU6.3 active at height 2
cd app && npm run demo         # the three escrows above
npm run ui                     # optional: the same flows in a browser at http://127.0.0.1:4747
npm test                       # verdict + adjudication unit tests
```

Check a verdict by itself:

```bash
npx tsx src/cli.ts verify ../.state/jobs/<job>/verdict.json [arbiter_pubkey_hex]
```

### Demo script for the stage (about 4 minutes)

1. `npm run ui`. Three cards: buyer, seller, arbiter. The arbiter card shows 0 ZEC, no wallet.
2. **New escrow**: a fresh FROST group is created and the buyer pays 1 ZEC. The log shows the
   shielded send and the escrow's Ironwood balance.
3. **Dispute: no delivery**. Evidence hashes go in, the verdict comes out (Ed25519), then
   buyer + arbiter co-sign the refund. Open **View verdict**: decision, reasons, evidence
   hashes, the exact payout, "signature valid".
4. Make the point with the CLI run (job B'): the arbiter was asked to sign a payout to the
   other side and refused. Its share is only usable for the verdict's payout.
5. **New escrow** → **Release**: buyer + seller pay out without the arbiter.

## How it works

```
buyer wallet ──(shielded send)──▶ escrow address  (FROST group key; 2-of-3: B, S, A)
                                        │
            ┌───────────────────────────┼─────────────────────────────┐
     buyer + seller               dispute: evidence → arbiter         │
     sign payout to seller        → signed verdict (Ed25519)          │
                                  → winner + arbiter sign exactly     │
                                    the verdict's payout              │
```

- **Per-job keys.** Every escrow gets its own FROST group and its own address. A share is
  only worth anything for the lifetime of one deal.
- **What the arbiter sees.** It never gets a viewing key. During a dispute it sees the
  evidence the parties choose to send (it stores only hashes in the verdict), and the PCZT it
  is asked to co-sign. The PCZT shows the escrowed amount and the payout output. It shows
  nothing about the parties' other funds.
- **What the chain sees.** One shielded deposit and one shielded payout, both v6 Ironwood
  transactions. FROST signatures look like single-signer RedPallas signatures.
- **Verdict ↔ transaction binding.** The verdict names the payout address and minimum
  amount. The arbiter signs only if the PCZT's outputs match it and the FROST message equals
  the sighash it computed itself. It records `{verdict_sha256, sighash}`, and the payout memo
  carries the verdict hash, so the recipient can link the two.

### Verdict format (`predge.zescrow.verdict/1`)

```json
{
  "verdict": {
    "schema": "predge.zescrow.verdict/1",
    "job_id": "C-…", "escrow_address": "u…", "group_ak": "dd…", "terms_sha256": "15…",
    "decision": "release_to_seller",
    "reasons": ["seller delivered, on time, a file matching the committed item hash", "…"],
    "evidence": [{ "party": "seller", "kind": "delivery", "sha256": "f382…", "submitted_at": "…", "note": "…" }],
    "payout": { "to": "u…", "party": "seller", "min_amount_zat": 299980000 },
    "cosigner_with": "seller",
    "issued_at": "…", "arbiter_pubkey": "a0ba…"
  },
  "signature": "Ed25519 over the canonical JSON (sorted keys, no whitespace)"
}
```

### The demo's adjudication rule (stub)

This rule is for sealed-listing digital goods. When the seller lists an item, it commits to
`sha256(deliverable)` in the terms. If the seller shows a delivery that matches that hash
and arrived before `deliver_by`, the seller is paid. Otherwise the buyer is refunded.

This rule is deliberately simple. It shows the shape of the system; it does not decide real
disputes. For example, it cannot prove the file was actually *sent* to the buyer. Real
disputes go through Predge's evidence review, which produces the same signed verdict object.
The signing path does not change.

## Answers to the committee's FROST questions

These are the problems raised when earlier FROST grants were reviewed (20 Jul minutes):
peer-to-peer messaging, transaction delivery, share backup, and recovery.

**Signer messaging.**
- *Today (MVP):* the coordinator relays only public data: commitments, signing packages,
  signature shares and the PCZT. Nonces and shares never leave a party's directory, and each
  nonce file is deleted the moment it is used.
- *Milestone 1:* use the Zcash Foundation's `frostd`, which was audited by Least Authority.
  Parties authenticate with communication keys. Round messages are end-to-end encrypted with
  Noise (`Noise_K_25519_ChaChaPoly_BLAKE2s` in `frost-client`), so the server sees only
  ciphertext and session metadata.
- *No dedicated server:* the coordinator can be the arbiter, the buyer, or a `frostd` that
  the parties pick. It is not trusted with funds. At worst it can refuse to relay.
- *Async disputes:* a party who goes offline just stops being one of the two signers. Any
  other pair can still finish.

**Transaction delivery.**
- The PCZT is built from a view-only wallet and proven once. Every signer re-checks it
  independently: outputs, then a sighash recomputed with `zcash-sign`.
- Broadcast is a plain `SendTransaction` to any lightwalletd/Zaino, so whoever finishes
  aggregation can broadcast.
- The payout memo carries the verdict hash for the recipient.

**Share backup.**
- Shares are per-escrow and short-lived. Losing one after payout costs nothing.
- While an escrow is open, back up two things:
  1. The share (32-byte scalar + group data, about 1 KB JSON). Milestone 2 encrypts it to the
     party's age identity, the same mechanism `zcash-devtool` uses for seeds.
  2. The escrow UFVK. It is needed to find the notes and build the payout. `zcash-sign` derives
     it with fresh randomness, so it **cannot** be recomputed from the group key. Every party
     stores a copy (it is a viewing key for this escrow only).

**Recovery.**
- *One share lost:* funds are not stuck, because the other two parties can still sign. For
  example, buyer + arbiter can refund if the seller disappears, and seller + arbiter can pay
  out if the buyer vanishes after delivery.
- *Restoring a lost share:* the other two parties can rebuild it without revealing their own
  shares. This uses the repairable threshold scheme, `reddsa::frost::redpallas::keys::repairable`
  (`repair_share_step_1..3`), already in the ZF crate. Wiring it into the CLI is milestone 2.
- *Two shares lost or colluding:* this is the trust assumption of any 2-of-3. Per-job keys
  keep the blast radius to one deal.
- *Arbiter disappears:* buyer + seller can still settle between themselves. Milestone 2 adds
  a deadline rule: after `deliver_by` plus a grace period, the client prompts buyer + seller to
  agree, or picks a backup arbiter named in the terms. A backup arbiter needs a 2-of-4 group;
  this is a protocol choice to settle in the spec.

## Known limits and upstream dependencies

- `zcash-sign generate` uses the Orchard `from_sk_ak` constructor, which upstream marks
  "incompatible with quantum recoverability and will be removed" (frost-tools #591).
  `orchard` is pinned to a fork carrying the FROST constructor (zcash/orchard#475). Both are
  ZF/ECC work in progress, and we will track them rather than fork.
- Zaino 0.10.2 cannot parse the NU7 consensus branch id (zingolabs/zaino#1655). The regtest
  chain therefore stops at NU6.3. Testnet already runs NU7; NU7 testing happens there, or
  against lightwalletd instead of Zaino.
- `zcash-devtool init-fvk` writes default regtest heights. The app pins them to the chain's
  heights (`pinHeights`).
- `zcash-sign` reads signatures from stdin, so the app drives it over a pipe. A
  non-interactive mode is a small upstream PR (milestone 3).
- `zcash-devtool` is a developer tool ("DO NOT USE IN PRODUCTION"). For production, the
  wallet side moves to Zallet's PCZT RPCs or to an existing wallet that supports FROST
  (Zkool) or the co-signing spec under review.

## Testnet

`ZESCROW_NETWORK=test` switches the app to the public testnet. What changes:
- wallets use `-n test` and the `zecrocks` lightwalletd; state lives in `.state-testnet/`;
- the escrow address and UFVK from `zcash-sign generate -n test` are used as they are (no
  regtest re-encode, no height pinning);
- there is no mining: the app polls the light wallets until the deposit is spendable (10
  confirmations) and until the payout is mined;
- the buyer is a pre-funded wallet in `.testnet-buyer/` (seed age-encrypted to
  `.testnet-buyer/identity.age`, both git-ignored). About 0.25 TAZ covers all three escrows.
- `zcash-sign sign` runs from a second build (`scripts/build-deps.sh --testnet`): the same
  frost-tools commit with `scripts/zcash-sign-nu7.patch`, which moves it to zcash-devtool's
  librustzcash rev so it knows the testnet NU7 branch id (`0x77190ad9`). The pinned build fails
  on testnet with `UnknownConsensusBranchId`. Only `sign` works in the patched build; orchard
  0.16 has no FROST FVK constructor, so `generate` still uses the pinned build.

```bash
./scripts/build-deps.sh --testnet
cd app && npm run testnet          # paths B (with B'), A, C; or: npm run testnet -- B
ZESCROW_NETWORK=test npx tsx src/cli.ts enforce <job>   # resume a funded job after an error
```

Results from 31.10.2026 are in the table under "What works today". In that run the buyer wallet
went from 1.0 TAZ to 0.89945 TAZ, and the seller wallet received 0.0998 TAZ. Fees were 0.00075 TAZ
in total (ZIP 317: 0.00025 for the first deposit, 0.0001 for each other transaction).

ZF frost-tools PR #593 already showed 2-of-3 FROST spends of Ironwood notes on public testnet
(txs `c5a1c4a1…410e`, `23ec9a37…7740`).

## Grant plan (ZCG, $15,000, 3 milestones)

Estimates assume one developer. They include review cycles with the FROST maintainers. Each
milestone ends with a public forum update.

| # | Deliverable | Effort | Amount |
|---|---|---|---|
| Startup | Spec draft published for comment; testnet deployment of this MVP | 1 week | $3,000 |
| M1 | **Protocol spec + test vectors**, reviewed by a FROST maintainer: roles, verdict format, verdict ↔ sighash binding, timeouts, what each party sees. **DKG** (ZF `frost` DKG) instead of the trusted dealer. **Signer messaging over ZF `frostd`** with end-to-end encryption. Runs on testnet. | 4 weeks | $4,500 |
| M2 | **Share backup and recovery**: age-encrypted share export/import, share repair via `repairable`, deadline/timeout handling, arbiter-unavailable path. A usable web flow for buyer and seller. One P2P integration partner on testnet, then a small mainnet pilot. | 4 weeks | $4,500 |
| M3 | **Independent review** of the escrow app and its signer policy checks. Fixes. Docs. Upstream PRs (non-interactive `zcash-sign`, regtest/network encoding in `zcash-sign generate`). Mainnet release. | 3 weeks | $3,000 |

Total: $15,000, about 12 weeks. That fits inside the $12–18k range and stays well under the
$50k KYC line. The startup amount and the milestone amounts add up exactly to the total, as FPF
requires. If the committee wants a larger upfront share, move $1,500 from M3 to the startup.

The committee is likely to push back on two things, and we would rather say so now:
- **The escrow layer has to be reusable.** The spec and the signer policy check should land
  where wallets can pick them up: the co-signing spec under review, Zkool, or the frost-tools
  docs. They should not exist only in this repo.
- **The arbiter must stay swappable.** Predge is one arbiter. Nothing in the protocol requires it.

## Layout

```
chain/            regtest compose file (Zebra 7.0.0 + Zaino 0.10.2), configs, activation heights
crates/zescrow-frost/  per-party FROST CLI over ZF reddsa / frost-rerandomized (no crypto of its own)
app/src/escrow.ts      protocol: jobs, funding, PCZT payout, signer checks, verdict enforcement
app/src/verdict.ts     verdict schema, Ed25519 signing, adjudication rule
app/src/cli.ts         demo + verify; app/src/server.ts + app/ui: demo UI
scripts/          build-deps.sh (pinned upstream tools), chain-up.sh, zcash-sign-nu7.patch (testnet signing)
```

License: MIT.
