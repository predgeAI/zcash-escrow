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

Status: working MVP on a private regtest chain. **Do not use with real funds.**

## What works today (verified by running it)

`npm run demo` runs three escrows end to end on a local Zebra 7.0.0 regtest chain. Each
payout below is a real v6 transaction, authorized by a 2-of-3 rerandomized FROST signature,
accepted by Zebra and mined.

| Path | Signers | Result in the last run |
|---|---|---|
| A. Release | buyer + seller | seller paid 0.9999 ZEC, tx `69167862…5f94` |
| B. Dispute, nothing delivered | buyer + arbiter | buyer refunded 1.9999 ZEC, tx `b1b985dd…00c5` |
| B'. Arbiter asked to pay the loser instead | arbiter alone checks | **refused**: "PCZT pays 0 zat to the agreed address" |
| C. Dispute, delivery proven | seller + arbiter | seller paid 2.9999 ZEC, tx `7d31c634…9734` |

The full run takes about 3.5 minutes on an M-series Mac. Proving takes about 3 s per payout.

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
| Network | regtest only. No working testnet faucet was reachable; the testnet path needs about 0.1 TAZ (see "Testnet"). |

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

The code is network-agnostic. Testnet needs:
- the `-n test` / `-s zecrocks` settings;
- dropping the regtest re-encode;
- a funded buyer wallet, about 0.1 TAZ.

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
scripts/          build-deps.sh (pinned upstream tools), chain-up.sh
```

License: MIT.
