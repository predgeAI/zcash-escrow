# Marketplace mode

Marketplace mode is for a P2P marketplace (the first one we built it for is CrowdStore). Today
CrowdStore's payment provider (PSP) holds the funds custodially. In marketplace mode, one
shielded 2-of-3 FROST escrow per deal holds them instead. Nobody can move the funds alone, and
the escrow can still pay out in several stages, to recipients and at times that were not known
when it was funded.

> **Trusted-dealer testnet demo.** Key shares come from a trusted dealer, the signers run in one
> process with a local relay, prices are set by hand and signed by a local quote key. Not for
> real funds.

The code is in `app/src/deal.ts` (the state machine and stage instructions), `app/src/pricelock.ts`
(price quotes), `app/src/marketplace.ts` (running it on an escrow) and `crates/zescrow-frost`
(the signer check, `--change-to-group`).

## CrowdStore's requirements and how each one is met

CrowdStore's own summary: *"Recipients, timing and ZEC amounts cannot all be fixed when the escrow
is funded."* So the escrow does not fix them at funding. It fixes the **rules**: the fiat terms,
the split, the keys allowed to sign events, instructions and quotes, and the escrow's own address
for change. Each stage then fixes its recipient, time and amount, and every signer checks that
stage against the rules before it signs.

| # | Requirement (verbatim) | Status | How |
|---|---|---|---|
| 1 | Convert ZEC into fiat during escrow and back to ZEC before payout (PriceLock). | **Partly met.** We do not convert to fiat. | The escrow stays in ZEC; the obligations are in fiat (USD cents). At each stage the ZEC amount is the fiat amount divided by the price in a signed quote. If ZEC has risen, the surplus goes to the marketplace's reserve address as an exact output of the same transaction. If ZEC has fallen, the escrow pays what it set aside and the instruction records a **reserve top-up**: the marketplace pays the difference from its own reserve, so the recipient still gets the fiat value. The marketplace's reserve carries the price risk, as it does with the PSP today. See "PriceLock" below. |
| 2 | Pay 95% to the seller, 4% to the buyer for a verified review, and keep a 1% fee, at different times. | **Met.** | Split `9500 / 400 / 100` bps (configurable) of the fiat amount, and of the ZEC principal at the funding quote. Each share is paid in its own stage, and each stage returns the rest to the escrow as change. |
| 3 | Issue full refunds without retaining our fee, or hold funds in disputed cases. | **Met.** | The `refund` stage returns every unpaid share to the buyer, the 1% fee included. If nothing has been paid yet, that is 100% of the fiat value. A `dispute_opened` event stops every stage until the arbiter signs a `dispute_resolved` event (`release_seller` or `refund_buyer`). |
| 4 | The buyer may claim the 4% review reward after the seller has already been paid. | **Met.** | The reward becomes payable on any verified review. That can happen before or after the seller payout. |
| 5 | A negative review earns the buyer's reward but freezes the seller's share. | **Met.** | A negative review makes the reward payable and moves the seller share to `frozen` if it is unpaid. A frozen share cannot be paid; the fee waits for the seller payout. |
| 6 | An updated review can release frozen funds, but cannot reverse an existing payout. | **Met.** | `review_updated` positive turns `frozen` back into `payable`. A payout is a mined transaction and the state machine never moves a share out of `paid`. A negative review after the seller was paid changes nothing for the seller. |
| 7 | Payout addresses may only become known later. | **Met**, with the operator trusted for the address unless the party has a key (below). | The terms hold no buyer or seller address. The address is supplied when a stage is created and bound into the signed stage instruction, as an operator attestation that it comes from the party's authenticated CrowdStore account. If the terms register an Ed25519 key for that party (`party_keys`), the party's own signature over `{deal_id, party, address}` is required too. |
| 8 | Refunds preserve the fiat escrow value, not the original ZEC amount. | **Met**, with the shortfall paid by the marketplace reserve. | A refund is computed in fiat at the refund quote. ZEC up: the buyer gets the fiat value in ZEC, the rest goes to the reserve. ZEC down: the escrow pays everything it holds for those shares and the reserve owes the difference. |

### What is **not** met, explicitly

- **No fiat conversion.** No fiat is held at any point. "PriceLock" here means fiat-denominated
  obligations settled in ZEC at the payout-time price. The price risk lies with the marketplace's
  reserve, as it does with the PSP today, and is not removed.
- **A shortfall is a promise, not escrowed money.** When ZEC falls, the instruction records the
  top-up the reserve owes, and the scenario pays it with an ordinary send from the reserve
  wallet. The escrow cannot force the marketplace to pay it. To make it enforceable, the
  marketplace would have to over-fund the escrow (for example, a 20% reserve margin per deal)
  and pay shortfalls from that margin.
- **The operator is trusted for facts.** Delivery, reviews and disputes reach the state machine as
  events signed by the operator. The policy co-signer checks that a stage follows from those
  events, not that a review is genuine. A lying operator plus the policy co-signer can pay the
  seller early. The operator cannot do it alone.
- **Unclaimed reward.** If the buyer never leaves a review, the 4% stays in the escrow. There is no
  expiry rule yet; one would be a `reward_expired` event that releases the share to the buyer or the
  marketplace.

## Roles and trust model

Default group: **2-of-3**. Each share holder runs its own copy of the state machine.

| Share | Who | Signs |
|---|---|---|
| `operator` | the marketplace (CrowdStore) | events (funded, delivered, reviews, dispute opened) and stage instructions; co-signs stages |
| `policy` | a **policy co-signer**: an automated service that holds no other authority | only stages that its own replica of the state machine produces from the signed events, each stage id once |
| `arbiter` | an **independent arbiter** chosen in the terms | `dispute_resolved` events; co-signs if the operator or the policy co-signer is unavailable |

- **Ordinary stages:** operator + policy. The arbiter does not need to be online.
- **Disputes:** nothing signs while a dispute is open. The policy co-signer refuses every stage
  until the arbiter's signed resolution is in the event log. Then the resulting stage is signed by
  operator + policy, or by arbiter + policy if the operator does not cooperate.
- **No one moves funds alone.** That holds only if the three shares are held by three independent
  parties. If CrowdStore runs both the operator and the policy co-signer, CrowdStore can move funds
  alone and the setup is custodial again. The policy co-signer must therefore be run by someone
  else: a second company, a buyer/seller representative, or a hosted service.
- **Predge does not need to hold a share.** Predge can be the arbiter or run the policy co-signer.
  Both roles are open code with signed inputs, and any party can run them.
- **Any two can move everything.** This is the assumption of any 2-of-3. Per-deal keys limit the
  damage to one deal.
- **Key generation is still a trusted dealer** in this demo (`zescrow-frost keygen --parties
  operator,policy,arbiter`). The dealer sees every share before it deletes its copy. Milestone 1
  replaces this with ZF FROST DKG.
- **The quote signer** is trusted for the price, within the tolerance. Each signer can pass its
  own reference price (`reference_price_micros`). A quote more than `price_tolerance_bps` (default
  100 bps) away from that price is then refused, so a compromised quote key cannot move amounts
  by more than the tolerance.

## Staged payouts: change only back to the escrow

Each stage is one transaction. It spends the escrow's note, pays the stage's outputs, and sends the
rest back to the **escrow group's own internal (change) address**. Every signer gives
`zescrow-frost sign-pczt` the stage's policy:

```
--to <recipient> --min <zat> --max <zat> --memo "zescrow stage <instruction hash>"
--exact <reserve>:<zat>                       # surplus, when ZEC rose
--change-to-group <escrow UFVK> --change-exact <zat>
```

On top of all the existing checks (each output opened against its note commitment, each paying
output's ciphertext opened, the payee memo, the ZIP 317 fee, the sighash), the signer:

- accepts change only to an address that decrypts with the **internal-scope IVK** of the escrow
  UFVK. The escrow's own external address is not change, and another key's address is not
  change. Any other output that is not a named payment is refused ("outputs to other addresses");
- requires the change to be exactly `--change-exact` (or at least `--change-min`);
- refuses a payment (not change) to either of the escrow's own addresses;
- in `sign-pczt`, requires the change UFVK's `ak` to be the FROST group key of the share that is
  signing. Change can only go back to the group that is signing, not to an escrow whose UFVK
  someone substituted;
- refuses outputs back to the escrow when there is no `--change-to-group` (the final stage, and
  every payout outside marketplace mode). Those payouts still empty the escrow.

The network fee for each stage is fixed in the instruction: ZIP 317 for one spend and the
stage's outputs plus the change output, 10,000 or 15,000 zat. `zcash-devtool pczt create` always
adds a change output, which on the last stage has zero value. It comes out of a network fee budget funded with the
deal (default 45,000 zat for three stages). The last stage empties the escrow and sends the
unused budget to the reserve. This assumes the escrow holds a single note, which is true when it
is funded once and each stage leaves one change note (`--target-note-count 1`). A wallet that
selects other notes produces a different fee or change, and the signers refuse that PCZT.

## Stage instructions (`predge.zescrow.verdict/3`, kind `stage`)

```json
{
  "instruction": {
    "schema": "predge.zescrow.verdict/3", "kind": "stage",
    "deal_id": "M-…", "terms_sha256": "…", "escrow_address": "u…", "group_ak": "…",
    "stage_id": "M-…/1-seller_payout", "seq": 1, "stage": "seller_payout",
    "transition": { "event": "seller_paid", "shares": ["seller"], "from": { "seller": "payable" }, "to": "paid" },
    "state_sha256": "…",
    "fiat_usd_cents": 190, "quote": { "quote": { "price_micros": 44000000, "…": "…" }, "signature": "…" },
    "due_zat": 4318181, "tranche_zat": 4750000,
    "recipient": { "party": "seller", "address": "u…", "attested_by": "operator", "source": "…" },
    "payments": [
      { "to": "u…seller", "party": "seller", "zat": 4318181, "purpose": "obligation" },
      { "to": "u…reserve", "party": "reserve", "zat": 431819, "purpose": "surplus" }
    ],
    "reserve_topup": null,
    "escrow_before_zat": 5045000, "network_fee_zat": 15000,
    "change": { "to": "escrow-internal", "zat": 280000 },
    "memo": "zescrow stage <first 32 hex of the body hash>",
    "issuer": "operator", "issuer_pubkey": "…", "issued_at": "…"
  },
  "signature": "Ed25519 over the canonical JSON of instruction"
}
```

A signer (`checkStage`) checks that:

1. the instruction is signed by the issuer the terms name (operator or arbiter);
2. the stage id is new: not in the executed stages, not in this signer's own one-shot ledger, and
   `seq` is the next stage. A **replayed stage is refused**, and on chain its notes are spent anyway;
3. the quote is signed by the terms' quote key, is fresh now (`quote_max_age_s`), is the median of
   its sources, and is within tolerance of the signer's own reference price, if it has one;
4. the instruction is **exactly** the stage that the signer's own state allows. The signer
   re-plans the stage from its replica, using the instruction's quote and address binding, and
   compares every field. Any other amount, recipient, change or transition is refused.

It then signs the PCZT only through the Rust check above, with the policy taken from the instruction.
`zescrow verify stage.json` checks an instruction's signature offline.

Events are one-shot, ordered, signed envelopes (`predge.zescrow.deal-event/1`, `seq` = previous + 1).
Each party folds the same event log and executed stages into the same state (`replay`).

## State machine

Shares: `locked → payable → paid`, `payable ⇄ frozen`, unpaid → `refunded` (fee: `waived`).

| Event / stage | Allowed when | Effect |
|---|---|---|
| `funded` | created | deposit must equal principal (fiat at the funding quote, fresh when the buyer paid) + network fee budget |
| `delivered` | funded, no dispute, no refund | seller `locked → payable` |
| `review` (positive / negative) | delivered, not yet reviewed | reward `→ payable`; negative: seller `payable/locked → frozen` (`paid` stays `paid`) |
| `review_updated` | after a review | positive: seller `frozen → payable`; negative: freezes what is unpaid; never reverses a payout |
| `dispute_opened` | funded, something unpaid | every stage refused |
| `dispute_resolved` (arbiter only) | dispute open | `release_seller`: seller `→ payable`; `refund_buyer`: only the refund stage may run |
| stage `seller_payout` | seller `payable` | seller `paid`; fee `→ payable` |
| stage `reward_payout` | reward `payable` (before or after the seller) | reward `paid` |
| stage `fee_payout` | seller `paid` | fee `paid` |
| stage `refund` | something unpaid, and the seller unpaid or an arbiter refund decision | every unpaid share to the buyer (fee waived) |

The deal closes when every share is settled and the escrow is empty.

## PriceLock

`zat = floor(usd_cents × 10^4 × 10^8 / price_micros)`. Prices are integers in USD micros per ZEC.

- At funding: principal = amount at the funding quote. Each share's **tranche** is its bps of the principal.
- At a stage: `due` = the shares' fiat at the stage quote. If `due ≤ tranche`, the recipient gets
  `due` and the surplus goes to the reserve in the same transaction. If `due > tranche`, the
  recipient gets the tranche from the escrow and `reserve_topup = due − tranche` is recorded for
  the marketplace to pay.
- Signers re-compute every amount from the quote. The instruction must match exactly (integer
  maths, no tolerance on amounts); the tolerance applies to the quote's price against a signer's
  reference.

**Quotes** (`predge.zescrow.quote/1`): `{pair: "ZEC/USD", price_micros, sources: [{name, price_micros}],
method: "median", issued_at, signer_pubkey}`, Ed25519-signed. For tests and testnet,
`localQuoteSigner` signs hand-set prices. **A real feed plugs in** by replacing only the price
source. A quote service fetches ZEC/USD from several exchanges (Kraken, Coinbase, Binance,
Gemini, …), drops stale or missing prices, takes the median and signs the same object
(`quoteMedian`). Each signer can run the same fetch itself and pass its own median as the
reference.

## Testnet run (path M)

```bash
./scripts/build-deps.sh --testnet   # zcash-devtool with the payment-uri patch, NU7 zcash-sign
cd app && npm run testnet -- M
```

A $2.00 deal is funded at $40/ZEC: 0.05 TAZ plus a 45,000 zat budget, so 5,045,000 zat. Then:

1. Seller payout before delivery: refused.
2. Delivered. Seller stage at $44/ZEC: seller 4,318,181 zat ($1.90), reserve 431,819 (surplus), fee
   15,000, change 280,000 back to the escrow. The policy co-signer refuses the same stage built with
   the remainder sent to the marketplace's own address.
3. Replay of stage 1: refused.
4. Negative review: the seller is already paid, so nothing is frozen or reversed, and the reward is
   claimable.
5. Reward stage at $38/ZEC: buyer 200,000 zat (its whole tranche), reserve top-up 10,526 owed
   (the $0.08 is 210,526 zat), fee 10,000, change 70,000.
6. Fee stage at $40/ZEC: marketplace 50,000 ($0.02), reserve 5,000 (unused budget), fee 15,000,
   no change. The escrow is empty.
7. The reserve pays the 10,526 zat top-up to the buyer.

The transaction ids are in the README and in `testnet-run-M-marketplace.log`.
