// zescrow CLI. `demo` runs all three paths end to end on the regtest chain; `testnet` runs them
// on the public Zcash testnet with small amounts (ZESCROW_NETWORK=test).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  STATE, arbiterRefusesWrongPayout, balance, createJob, enforceVerdict, fmt, fund, issueVerdict,
  listJobs, release, setup, submitEvidence, walletDir,
} from "./escrow.ts";
import { verifyVerdict, type SignedVerdict } from "./verdict.ts";
import { TESTNET, say } from "./tools.ts";

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
  if (!TESTNET) throw new Error("run with ZESCROW_NETWORK=test");
  const t0 = Date.now();
  await setup();
  const run = Date.now().toString(36);
  const ids: string[] = [];
  for (const path of paths) {
    if (path === "B") {
      const doc = Buffer.from("translated-contract.pdf " + run);
      const b = createJob(`B-${run}`, { name: "Contract translation", bytes: doc, price_zat: 0.1 * ZEC });
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
      const a = createJob(`A-${run}`, { name: "Logo pack (digital goods)", bytes: logo, price_zat: 0.05 * ZEC });
      ids.push(a.id);
      await fund(a.id);
      submitEvidence(a.id, "seller", "delivery", "sent logo-pack.zip", logo);
      await release(a.id);
    } else if (path === "C") {
      const data = Buffer.from("weather-dataset.csv " + run);
      const c = createJob(`C-${run}`, { name: "Weather dataset", bytes: data, price_zat: 0.05 * ZEC });
      ids.push(c.id);
      await fund(c.id);
      submitEvidence(c.id, "seller", "delivery", "sent weather-dataset.csv", data);
      submitEvidence(c.id, "buyer", "complaint", "this is not what I ordered", Buffer.from("complaint " + run));
      submitEvidence(c.id, "buyer", "received_file", "the file I got", data);
      issueVerdict(c.id);
      await enforceVerdict(c.id);
    } else throw new Error(`unknown path ${path}`);
  }
  say("== summary (testnet)");
  for (const j of listJobs().filter((j) => ids.includes(j.id))) {
    say(`  ${j.id.padEnd(12)} ${j.state.padEnd(9)} ${fmt(j.funded_zat ?? 0)}  fund tx ${j.fund_txid} @${j.fund_height}  payout tx ${j.payout_txid} @${j.payout_height}`);
  }
  say(`  buyer wallet now ${fmt(balance(walletDir("buyer")).total)}, seller ${fmt(balance(walletDir("seller")).total)}`);
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
      return testnet(args.length ? args : ["B", "A", "C"]);
    case "verify": {
      const sv = JSON.parse(readFileSync(args[0], "utf8")) as SignedVerdict;
      const ok = verifyVerdict(sv, args[1]);
      console.log(ok ? `valid verdict: ${sv.verdict.decision} for ${sv.verdict.job_id}, pay ${sv.verdict.payout.party}` : "INVALID verdict");
      process.exit(ok ? 0 : 1);
    }
    case "status":
      for (const j of listJobs()) console.log(`${j.id}\t${j.state}\t${j.escrow_address.slice(0, 24)}…\t${j.payout_txid ?? ""}`);
      return;
    default:
      console.log("usage: zescrow demo | testnet [B A C] | release <job> | enforce <job> | setup | status | verify <verdict.json> [arbiter_pubkey_hex]");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
