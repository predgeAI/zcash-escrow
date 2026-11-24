// zescrow CLI. `demo` runs all three paths end to end on the regtest chain; `testnet` runs them
// on the public Zcash testnet with small amounts (ZESCROW_NETWORK=test).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  STATE, arbiterRefusesWrongPayout, balance, createJob, enforceVerdict, ensureMarketplaceWallet, fmt, fund, issueVerdict,
  listJobs, release, setup, signersRefuseMissingFee, submitEvidence, walletDir,
} from "./escrow.ts";
import { verdictPayments, verifyCanonical, verifyVerdict, type SignedVerdict } from "./verdict.ts";
import { marketplaceScenario } from "./marketplace.ts";
import { orderPayScenario } from "./orderpay.ts";
import type { SignedStage } from "./deal.ts";
import { MAINNET, NETWORK, TESTNET, say } from "./tools.ts";

const ZEC = 100_000_000;

export async function demo() {
  if (TESTNET) throw new Error("demo is regtest only; on testnet use `npm run testnet`");
  const t0 = Date.now();
  await setup();
  const before = { buyer: balance(join(STATE, "parties/buyer/wallet")).total, seller: balance(join(STATE, "parties/seller/wallet")).total };
  const run = Date.now().toString(36);

  // 1) Happy path: no arbiter involvement at all.
  const logo = Buffer.from("logo-pack.zip bytes " + run);
  const a = createJob(`A-${run}`, { name: "Logo pack (digital goods)", bytes: logo, price_zat: 1 * ZEC });
  await fund(a.id);
  submitEvidence(a.id, "seller", "delivery", "sent logo-pack.zip", logo);
  await release(a.id);

  // 2) Dispute, buyer wins: seller never delivers a file matching the listing.
  const doc = Buffer.from("translated-contract.pdf " + run);
  const b = createJob(`B-${run}`, { name: "Contract translation", bytes: doc, price_zat: 2 * ZEC });
  await fund(b.id);
  submitEvidence(b.id, "buyer", "complaint", "deadline passed, nothing delivered", Buffer.from("complaint " + run));
  submitEvidence(b.id, "seller", "delivery", "sent a draft", Buffer.from("half-finished draft " + run));
  issueVerdict(b.id);
  say("  try: ask the arbiter to co-sign a payout to the seller instead");
  say(`  -> ${await arbiterRefusesWrongPayout(b.id)}`);
  await enforceVerdict(b.id);

  // 3) Dispute, seller wins: buyer claims a wrong file, but the delivery matches the commitment.
  const data = Buffer.from("weather-dataset.csv " + run);
  const c = createJob(`C-${run}`, { name: "Weather dataset", bytes: data, price_zat: 3 * ZEC });
  await fund(c.id);
  submitEvidence(c.id, "seller", "delivery", "sent weather-dataset.csv", data);
  submitEvidence(c.id, "buyer", "complaint", "this is not what I ordered", Buffer.from("complaint " + run));
  submitEvidence(c.id, "buyer", "received_file", "the file I got", data);
  issueVerdict(c.id);
  await enforceVerdict(c.id);

  const after = { buyer: balance(join(STATE, "parties/buyer/wallet")).total, seller: balance(join(STATE, "parties/seller/wallet")).total };
  say("== summary");
  for (const j of listJobs().filter((j) => j.id.endsWith(run))) {
    say(`  ${j.id.padEnd(12)} ${j.state.padEnd(9)} ${fmt(j.funded_zat ?? 0)}  payout tx ${j.payout_txid}`);
  }
  say(`  seller received ${fmt(after.seller - before.seller)} (jobs A and C, minus fees)`);
  say(`  buyer net ${fmt(after.buyer - before.buyer)} (paid A and C, refunded B; includes coinbase mined to the buyer)`);
  say(`  done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
}

/**
 * Public testnet: same protocol, small amounts, one path at a time in priority order
 * (B dispute refund with the B' refusal, A release, C dispute payout to the seller).
 * Each escrow waits for real confirmations, so this takes roughly 15 minutes per path.
 */
export async function testnet(paths: string[]) {
  if (!TESTNET) throw new Error("run with ZESCROW_NETWORK=test (or =main for real ZEC)");
  if (MAINNET && process.env.CONFIRM_MAINNET !== "zcash") throw new Error("mainnet spends real ZEC: set CONFIRM_MAINNET=zcash");
  // Mainnet: a fifth of the testnet amounts (0.02 ZEC for all three paths).
  const k = MAINNET ? 0.2 : 1;
  const t0 = Date.now();
  await setup();
  const run = Date.now().toString(36);
  const ids: string[] = [];
  for (const path of paths) {
    if (path === "B") {
      const doc = Buffer.from("translated-contract.pdf " + run);
      const b = createJob(`B-${run}`, { name: "Contract translation", bytes: doc, price_zat: Math.round(0.1 * k * ZEC) });
      ids.push(b.id);
      await fund(b.id);
      submitEvidence(b.id, "buyer", "complaint", "deadline passed, nothing delivered", Buffer.from("complaint " + run));
      submitEvidence(b.id, "seller", "delivery", "sent a draft", Buffer.from("half-finished draft " + run));
      issueVerdict(b.id);
      say("  try: ask the arbiter to co-sign a payout to the seller instead");
      say(`  -> ${await arbiterRefusesWrongPayout(b.id)}`);
      await enforceVerdict(b.id);
    } else if (path === "A") {
      const logo = Buffer.from("logo-pack.zip bytes " + run);
      const a = createJob(`A-${run}`, { name: "Logo pack (digital goods)", bytes: logo, price_zat: Math.round(0.05 * k * ZEC) });
      ids.push(a.id);
      await fund(a.id);
      submitEvidence(a.id, "seller", "delivery", "sent logo-pack.zip", logo);
      await release(a.id);
    } else if (path === "AF") {
      // A with a marketplace fee: 2.5% of the price to the marketplace, fixed in the terms.
      const logo = Buffer.from("logo-pack.zip bytes " + run);
      const mkt = ensureMarketplaceWallet();
      const a = createJob(`AF-${run}`, {
        name: "Logo pack (digital goods)", bytes: logo, price_zat: Math.round(0.05 * k * ZEC),
        marketplace_fee: { address: mkt, bps: 250, on_refund: "keep" },
      });
      ids.push(a.id);
      await fund(a.id);
      submitEvidence(a.id, "seller", "delivery", "sent logo-pack.zip", logo);
      say("  try: ask the signers to release everything to the seller, skipping the marketplace fee");
      say(`  -> ${await signersRefuseMissingFee(a.id)}`);
      await release(a.id);
    } else if (path === "M") {
      // Marketplace mode: staged payouts with change back to the escrow, fiat terms, PriceLock.
      if (MAINNET) throw new Error("path M runs on testnet only");
      await marketplaceScenario({ fixtures: process.env.ZESCROW_FIXTURES, resume: process.env.ZESCROW_RESUME });
    } else if (path === "OPA" || path === "OPB") {
      // Milestone order (25% on preview, 75% on acceptance) paid to a seller address from the
      // environment; A is the normal path, B a dispute refunded to the client. Testnet only.
      if (MAINNET) throw new Error("path OP runs on testnet only");
      const seller = process.env.ORDERPAY_SELLER;
      if (!seller) throw new Error("set ORDERPAY_SELLER to the seller's testnet address");
      await orderPayScenario(path === "OPA" ? "A" : "B", {
        seller, priceMicros: Number(process.env.ORDERPAY_PRICE_MICROS ?? 4_000_000_000),
        amountCents: Number(process.env.ORDERPAY_USD_CENTS ?? 20_000), resume: process.env.ZESCROW_RESUME,
      });
    } else if (path === "C") {
      const data = Buffer.from("weather-dataset.csv " + run);
      const c = createJob(`C-${run}`, { name: "Weather dataset", bytes: data, price_zat: Math.round(0.05 * k * ZEC) });
      ids.push(c.id);
      await fund(c.id);
      submitEvidence(c.id, "seller", "delivery", "sent weather-dataset.csv", data);
      submitEvidence(c.id, "buyer", "complaint", "this is not what I ordered", Buffer.from("complaint " + run));
      submitEvidence(c.id, "buyer", "received_file", "the file I got", data);
      issueVerdict(c.id);
      await enforceVerdict(c.id);
    } else throw new Error(`unknown path ${path}`);
  }
  say(`== summary (${NETWORK})`);
  for (const j of listJobs().filter((j) => ids.includes(j.id))) {
    say(`  ${j.id.padEnd(12)} ${j.state.padEnd(9)} ${fmt(j.funded_zat ?? 0)}  fund tx ${j.fund_txid} @${j.fund_height}  payout tx ${j.payout_txid} @${j.payout_height}`);
  }
  say(`  buyer wallet now ${fmt(balance(walletDir("buyer")).total)}, seller ${fmt(balance(walletDir("seller")).total)}` +
    (paths.includes("AF") ? `, marketplace ${fmt(balance(walletDir("marketplace")).total)}` : ""));
  say(`  done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case "demo":
      return demo();
    case "setup":
      return setup();
    case "release":
      return void (await release(args[0]));
    case "enforce":
      return void (await enforceVerdict(args[0]));
    case "testnet":
    case "mainnet":
      return testnet(args.length ? args : ["B", "A", "C"]);
    case "verify": {
      const parsed = JSON.parse(readFileSync(args[0], "utf8")) as SignedVerdict | SignedStage;
      if ("instruction" in parsed) {
        // A marketplace stage instruction (predge.zescrow.verdict/3): signature and contents.
        const ins = parsed.instruction;
        const ok = verifyCanonical(ins, parsed.signature, args[1] ?? ins.issuer_pubkey) && (!args[1] || ins.issuer_pubkey === args[1]);
        console.log(ok
          ? `valid stage (${ins.schema}): ${ins.stage_id} ${ins.transition.event} signed by the ${ins.issuer}; pays ${ins.payments.map((p) => `${p.party} ${p.zat}`).join(", ")} zat; change ${ins.change?.zat ?? 0}; memo "${ins.memo}"`
          : "INVALID stage instruction");
        process.exit(ok ? 0 : 1);
      }
      const sv = parsed;
      const ok = verifyVerdict(sv, args[1]);
      const pays = ok ? verdictPayments(sv.verdict).map((p) => `${p.party} ${p.min_amount_zat}${p.max_amount_zat !== undefined && p.max_amount_zat !== p.min_amount_zat ? `..${p.max_amount_zat}` : ""} zat`).join(", ") : "";
      console.log(ok ? `valid verdict (${sv.verdict.schema}): ${sv.verdict.decision} for ${sv.verdict.job_id}, pay ${pays}` : "INVALID verdict");
      process.exit(ok ? 0 : 1);
    }
    case "status":
      for (const j of listJobs()) console.log(`${j.id}\t${j.state}\t${j.escrow_address.slice(0, 24)}…\t${j.payout_txid ?? ""}`);
      return;
    default:
      console.log("usage: zescrow demo | testnet [B A C AF M OPA OPB] | release <job> | enforce <job> | setup | status | verify <verdict.json> [arbiter_pubkey_hex]");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
