// The escrow protocol, end to end, on top of existing Zcash tooling.
//
// Roles and what each one holds (one directory per party under .state/parties):
//   buyer   : own zcash-devtool wallet (seed) + its FROST share for each job
//   seller  : own zcash-devtool wallet (seed) + its FROST share for each job
//   arbiter : its FROST share for each job + an Ed25519 verdict key. No wallet, no seed.
// The escrow address itself is a FROST group key: 2 of {buyer, seller, arbiter} must sign.
// The coordinator (this process) only relays public round messages and PCZTs; it holds no secret.
// Network: regtest by default; ZESCROW_NETWORK=test runs on the public testnet (see tools.ts).

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { checkPayout, expectFromPayments, signPayout, type Expect } from "./payout-check.ts";
import { BIN, LIGHTWALLETD, MAINNET, NET, NETWORK, ROOT, TESTNET, devtool, frost, mine, rpc, say, zcashSign } from "./tools.ts";
import {
  FEE_ALLOWANCE_ZAT, adjudicate, canonical, loadArbiterKey, marketplaceFeeZat, sha256, signVerdict, splitPayout,
  validateMarketplaceFee, verdictPayments, verifyVerdict,
  type Decision, type EvidenceItem, type MarketplaceFee, type Payment, type SignedVerdict, type Terms, type Verdict,
} from "./verdict.ts";

export const STATE = process.env.ZESCROW_STATE ?? join(ROOT, MAINNET ? ".state-mainnet" : TESTNET ? ".state-testnet" : ".state");
// Testnet has no coinbase faucet: the buyer is a wallet funded beforehand (seed age-encrypted inside it).
const TESTNET_BUYER = process.env.ZESCROW_BUYER_WALLET ?? join(ROOT, MAINNET ? ".mainnet-buyer" : ".testnet-buyer");
const HEIGHTS = join(ROOT, "chain/activation-heights.toml");
const COMPOSE = join(ROOT, "chain/compose.yaml");
// FEE_ALLOWANCE_ZAT (verdict.ts) is funding headroom and the bound on the winner's payout. The fee
// itself is not taken on trust: every signer requires it to be exactly the ZIP 317 conventional
// fee (5,000 zat x max(2, actions)).

type Party = "buyer" | "seller" | "arbiter";
// "marketplace" only holds a wallet to receive fees (demo/testnet); it never holds a FROST share.
type WalletParty = "buyer" | "seller" | "marketplace";
const partyDir = (p: Party | "marketplace") => join(STATE, "parties", p);
export const walletDir = (p: WalletParty) => (TESTNET && p === "buyer" ? TESTNET_BUYER : join(partyDir(p), "wallet"));
const ageFile = (p: WalletParty) => (TESTNET && p === "buyer" ? join(TESTNET_BUYER, "identity.age") : join(partyDir(p), "wallet.age"));
const jobDir = (job: string) => join(STATE, "jobs", job);
const shareFile = (p: Party, job: string) => join(partyDir(p), "shares", `${job}.key.json`);
const readJson = <T>(p: string): T => JSON.parse(readFileSync(p, "utf8")) as T;
const writeJson = (p: string, v: unknown) => {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, JSON.stringify(v, null, 2));
};

export interface Job {
  id: string;
  terms: Terms;
  terms_sha256: string;
  escrow_address: string;
  escrow_ufvk: string;
  group_ak: string;
  funded_zat?: number;
  fund_txid?: string;
  fund_height?: number;
  state: "created" | "funded" | "released" | "refunded";
  payout_txid?: string;
  payout_height?: number;
  verdict_sha256?: string;
}

// ---------- wallets and chain ----------

function orchardAddress(dir: string): string {
  const out = devtool(["wallet", "-w", dir, "list-addresses", "--receiver", "orchard"], { quiet: true });
  const m = /Receiver\(orchard\): (\S+)/.exec(out);
  if (!m) throw new Error(`no orchard receiver in ${dir}`);
  return m[1];
}

export function balance(dir: string): { ironwood: number; total: number; tip: number } {
  devtool(["wallet", "-w", dir, "sync", "-s", LIGHTWALLETD], { quiet: true });
  const j = JSON.parse(devtool(["wallet", "-w", dir, "balance", "--json"], { quiet: true }).trim().split("\n").pop()!);
  return { ironwood: j.ironwood_spendable, total: j.total, tip: j.chain_tip_height };
}

/** Height at which `txid` was mined, as seen by the wallet in `dir` (sync it first). */
function minedHeight(dir: string, txid: string): number | undefined {
  const txs = JSON.parse(devtool(["wallet", "-w", dir, "list-tx", "--json"], { quiet: true }).trim().split("\n").pop()!) as
    { txid: string; mined_height: number | null }[];
  return txs.find((t) => t.txid === txid)?.mined_height ?? undefined;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Testnet: no mining, so poll the light wallet until `done` holds (blocks are ~75 s apart). */
async function waitChain(what: string, done: () => { ok: boolean; tip: number }, minutes = 90) {
  const until = Date.now() + minutes * 60_000;
  let shown = 0;
  for (;;) {
    const { ok, tip } = done();
    if (ok) return tip;
    if (Date.now() > until) throw new Error(`timed out after ${minutes} min waiting for ${what} (tip ${tip})`);
    if (tip !== shown) say(`  waiting for ${what}, testnet tip ${tip}`);
    shown = tip;
    await sleep(20_000);
  }
}

/** zcash-devtool's view-only import writes its built-in regtest heights; make them match the chain. */
function pinHeights(dir: string) {
  const cfg = join(dir, "keys.toml");
  const heights = readFileSync(HEIGHTS, "utf8");
  const nu7 = /^nu7 = (.*)$/m.exec(heights)?.[1] ?? '"never"';
  writeFileSync(cfg, readFileSync(cfg, "utf8").replace(/^nu7 = .*$/m, `nu7 = ${nu7}`));
}

export function partyAddress(p: WalletParty): string {
  return orchardAddress(walletDir(p));
}

/** A receive-only wallet for the marketplace's fee address (demo and testnet runs). */
export function ensureMarketplaceWallet(): string {
  const w = walletDir("marketplace");
  if (!existsSync(join(w, "keys.toml"))) {
    mkdirSync(partyDir("marketplace"), { recursive: true });
    if (TESTNET) devtool(["wallet", "-w", w, "init", "--name", "marketplace", "-i", ageFile("marketplace"), "-n", NET, "-s", LIGHTWALLETD]);
    else devtool(["wallet", "-w", w, "init", "--name", "marketplace", "-i", ageFile("marketplace"), "-n", "regtest",
      "--activation-heights", HEIGHTS, "-s", LIGHTWALLETD]);
  }
  return partyAddress("marketplace");
}

/** One-time: party wallets, arbiter verdict key, and point Zebra's coinbase at the buyer. */
export async function setup(): Promise<void> {
  say(`== setup: party wallets and arbiter key (${NETWORK})`);
  if (TESTNET && !existsSync(join(walletDir("buyer"), "keys.toml"))) {
    throw new Error(`testnet buyer wallet missing at ${walletDir("buyer")}; create and fund it first (${MAINNET ? "about 0.025 ZEC" : "about 0.1 TAZ"})`);
  }
  for (const p of ["buyer", "seller"] as const) {
    if (existsSync(join(walletDir(p), "keys.toml"))) continue;
    mkdirSync(partyDir(p), { recursive: true });
    if (TESTNET) {
      devtool(["wallet", "-w", walletDir(p), "init", "--name", p, "-i", ageFile(p), "-n", NET, "-s", LIGHTWALLETD]);
      continue;
    }
    devtool(["wallet", "-w", walletDir(p), "init", "--name", p, "-i", ageFile(p), "-n", "regtest",
      "--activation-heights", HEIGHTS, "-s", LIGHTWALLETD]);
  }
  const arb = loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));
  say(`  arbiter verdict key ${arb.pubHex}`);
  if (TESTNET) return;
  const buyerUa = partyAddress("buyer");
  const info = readMeta();
  if (info.miner !== buyerUa) {
    say("  pointing Zebra's shielded coinbase at the buyer (regtest faucet)");
    const r = spawnSync("docker", ["compose", "-f", COMPOSE, "up", "-d", "zebra"], {
      env: { ...process.env, MINER_ADDRESS: buyerUa }, encoding: "utf8",
    });
    if (r.status !== 0) throw new Error(r.stderr);
    for (let i = 0; i < 60; i++) {
      try { await rpc("getblockcount"); break; } catch { await new Promise((r) => setTimeout(r, 1000)); }
    }
    writeJson(join(STATE, "meta.json"), { ...info, miner: buyerUa });
  }
}

function readMeta(): { miner?: string } {
  const p = join(STATE, "meta.json");
  return existsSync(p) ? readJson(p) : {};
}

/** Regtest only: mine shielded coinbase to the buyer until it can pay `need` zat. */
export async function ensureBuyerFunds(need: number) {
  let b = balance(walletDir("buyer"));
  if (b.ironwood >= need) return;
  if (TESTNET) {
    // Change from an earlier payment needs a few confirmations before it is spendable again.
    if (b.total < need) throw new Error(`testnet buyer holds ${fmt(b.total)}, needs ${fmt(need)}`);
    await waitChain(`buyer to have ${fmt(need)} spendable`, () => { b = balance(walletDir("buyer")); return { ok: b.ironwood >= need, tip: b.tip }; });
    return;
  }
  say(`  buyer has ${fmt(b.ironwood)} spendable; mining coinbase to the buyer`);
  await mine(101);
  await waitIndexer();
  b = balance(walletDir("buyer"));
  if (b.ironwood < need) throw new Error("buyer still underfunded after mining");
}

async function waitIndexer() {
  // Zaino follows Zebra with a short delay; wait until the light wallet sees Zebra's tip.
  const tip = await rpc<number>("getblockcount");
  for (let i = 0; i < 60; i++) {
    const out = devtool(["wallet", "-w", walletDir("buyer"), "sync", "-s", LIGHTWALLETD], { quiet: true });
    void out;
    const j = JSON.parse(devtool(["wallet", "-w", walletDir("buyer"), "balance", "--json"], { quiet: true }).trim().split("\n").pop()!);
    if (j.chain_tip_height >= tip) return;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("light wallet did not catch up with Zebra");
}

export const fmt = (zat: number) => `${(zat / 1e8).toFixed(8)} ${NETWORK === "test" ? "TAZ" : "ZEC"}`;

// ---------- job lifecycle ----------

/** Seller lists an item (commits to its hash); a fresh 2-of-3 FROST escrow is created for the job. */
export function createJob(id: string, item: { name: string; bytes: Buffer; price_zat: number; deliver_in_s?: number; marketplace_fee?: MarketplaceFee }): Job {
  say(`== job ${id}: create escrow for "${item.name}" at ${fmt(item.price_zat)}`);
  if (existsSync(jobDir(id))) rmSync(jobDir(id), { recursive: true });
  for (const p of ["buyer", "seller", "arbiter"] as const) rmSync(shareFile(p, id), { force: true });
  const terms: Terms = {
    item: item.name,
    price_zat: item.price_zat,
    item_sha256: sha256(item.bytes),
    deliver_by: new Date(Date.now() + (item.deliver_in_s ?? 3600) * 1000).toISOString(),
    buyer_refund_address: partyAddress("buyer"),
    seller_payout_address: partyAddress("seller"),
  };
  // Only set when present, so terms (and their hash) without a fee are byte-for-byte unchanged.
  if (item.marketplace_fee) {
    terms.marketplace_fee = item.marketplace_fee;
    validateMarketplaceFee(terms);
    const f = item.marketplace_fee;
    say(`  marketplace fee ${f.bps !== undefined ? `${f.bps} bps` : "fixed"} = ${fmt(marketplaceFeeZat(terms))} to ${f.address.slice(0, 20)}…, on refund: ${f.on_refund}`);
  }
  // Trusted-dealer keygen (MVP). Each share is written to its party's own directory; the
  // dealer copy is deleted. Milestone 2 replaces this with ZF frost DKG over frostd.
  const tmp = join(jobDir(id), "dealer");
  frost(["keygen", "--out", tmp]);
  for (const p of ["buyer", "seller", "arbiter"] as const) {
    mkdirSync(join(partyDir(p), "shares"), { recursive: true });
    writeFileSync(shareFile(p, id), readFileSync(join(tmp, `${p}.key.json`)), { mode: 0o600 });
  }
  writeFileSync(join(jobDir(id), "group.json"), readFileSync(join(tmp, "group.json")));
  rmSync(tmp, { recursive: true });
  const ak = frost(["ak", "--group", join(jobDir(id), "group.json")]).trim();
  // ZF zcash-sign derives the escrow's full viewing key and address from the group key.
  // It encodes for testnet; on regtest the app re-encodes the same keys with the regtest HRPs.
  const gen = spawnSync(BIN.zcashSign, ["generate", "--ak", ak, "-n", NET], { encoding: "utf8" });
  if (gen.status !== 0) throw new Error(gen.stderr);
  const ua = /address: "(\S+)"/.exec(gen.stdout)![1];
  const ufvk = /Viewing Key: "(\S+)"/.exec(gen.stdout)![1];
  const enc = (v: string) => (TESTNET ? v : frost(["reencode", "--value", v, "--network", "regtest"]).trim());
  const job: Job = {
    id, terms, terms_sha256: sha256(canonical(terms)), group_ak: ak, state: "created",
    escrow_address: enc(ua),
    escrow_ufvk: enc(ufvk),
  };
  const w = join(jobDir(id), "wallet");
  // Birthday defaults to the current tip, so the view-only wallet never scans old blocks.
  devtool(["wallet", "-w", w, "init-fvk", "--name", `escrow-${id}`, "--fvk", job.escrow_ufvk, "-s", LIGHTWALLETD], { quiet: true });
  if (!TESTNET) pinHeights(w);
  writeJson(join(jobDir(id), "terms.json"), terms);
  saveJob(job);
  say(`  escrow address ${job.escrow_address.slice(0, 32)}…  (FROST group key ${ak.slice(0, 16)}…)`);
  return job;
}

export const loadJob = (id: string) => readJson<Job>(join(jobDir(id), "job.json"));
const saveJob = (j: Job) => writeJson(join(jobDir(j.id), "job.json"), j);
export const listJobs = (): Job[] =>
  existsSync(join(STATE, "jobs")) ? readdirSync(join(STATE, "jobs")).filter((d) => existsSync(join(jobDir(d), "job.json"))).map(loadJob) : [];

/** Buyer pays the price into the FROST escrow address (an ordinary shielded payment). */
export async function fund(id: string): Promise<Job> {
  const job = loadJob(id);
  say(`== job ${id}: buyer funds the escrow`);
  await ensureBuyerFunds(job.terms.price_zat + FEE_ALLOWANCE_ZAT);
  const out = devtool(["wallet", "-w", walletDir("buyer"), "send", "-i", ageFile("buyer"), "--address", job.escrow_address,
    "--value", String(job.terms.price_zat), "--memo", `zescrow fund ${id} terms ${job.terms_sha256.slice(0, 16)}`, "-s", LIGHTWALLETD]);
  job.fund_txid = out.trim().split("\n").pop();
  saveJob(job);
  const ew = join(jobDir(id), "wallet");
  if (TESTNET) {
    // The deposit is spendable by the escrow after 10 confirmations (zcash-devtool's untrusted-note policy).
    say(`  fund tx ${job.fund_txid}`);
    await waitChain("the deposit to confirm in the escrow wallet", () => { const b = balance(ew); return { ok: b.ironwood >= job.terms.price_zat, tip: b.tip }; }, 120);
    job.fund_height = minedHeight(ew, job.fund_txid!);
  } else {
    await mine(10);
    await waitIndexer();
  }
  const b = balance(ew);
  if (b.ironwood < job.terms.price_zat) throw new Error(`escrow shows ${b.ironwood} zat, expected ${job.terms.price_zat}`);
  job.funded_zat = b.ironwood;
  job.state = "funded";
  saveJob(job);
  say(`  escrow holds ${fmt(b.ironwood)} in the Ironwood pool (tx ${job.fund_txid?.slice(0, 16)}…)`);
  return job;
}

// ---------- payout: PCZT + 2-of-3 FROST ----------

async function frostSign(job: Job, signers: [Party, Party], pczt: string, expect: Expect,
  arbiterGate?: (sighash: string) => void): Promise<string> {
  const dir = join(jobDir(job.id), "rounds");
  mkdirSync(dir, { recursive: true });
  const group = join(jobDir(job.id), "group.json");
  const signed = pczt.replace(/\.pczt$/, ".signed.pczt");
  await zcashSign(pczt, signed, async (sighash, rands) => {
    say(`  sighash ${sighash.slice(0, 16)}…, ${rands.length} spend(s) to authorize; signers: ${signers.join(" + ")}`);
    const sigs: string[] = [];
    for (const r of rands) {
      // Round 1: each signer commits with fresh nonces (kept in its own directory).
      for (const p of signers) {
        frost(["commit", "--key", shareFile(p, job.id), "--nonces-out", join(partyDir(p), "nonces", `${job.id}-${r.index}.json`),
          "--commitments-out", join(dir, `${p}-${r.index}.commit.json`)]);
      }
      const pkg = join(dir, `package-${r.index}.json`);
      frost(["package", "--message", sighash, "--commitments", ...signers.map((p) => join(dir, `${p}-${r.index}.commit.json`)), "--out", pkg]);
      // Round 2: each signer checks the PCZT and signs in one `zescrow-frost sign-pczt` call, which
      // reads the PCZT once, checks outputs (commitments, ciphertexts, memo), fee and payout, derives
      // the sighash from those bytes and refuses a package with any other message.
      for (const p of signers) {
        let own;
        try {
          own = signPayout(pczt, expect, {
            key: shareFile(p, job.id), nonces: join(partyDir(p), "nonces", `${job.id}-${r.index}.json`),
            package: pkg, randomizer: r.alpha, out: join(dir, `${p}-${r.index}.share.json`),
          });
        } catch (e) {
          throw new Error(`${p} refuses: ${(e as Error).message}`);
        }
        if (p === "arbiter") arbiterGate?.(own.sighash);
        say(`  ${p} checked the PCZT (fee ${own.fee} zat, memo verified) and produced a signature share`);
      }
      sigs.push(frost(["aggregate", "--group", group, "--package", pkg, "--randomizer", r.alpha,
        "--shares", ...signers.map((p) => join(dir, `${p}-${r.index}.share.json`))]).trim());
    }
    say("  aggregated a RedPallas spend-auth signature (verified against the rerandomized key)");
    return sigs;
  });
  return signed;
}

/** ZIP 321 payment request URI (amounts in ZEC, memos base64url without padding). */
export function zip321Uri(payments: { to: string; amount_zat: number; memo?: string }[]): string {
  const zec = (z: number) => {
    const s = `${Math.floor(z / 1e8)}.${String(z % 1e8).padStart(8, "0")}`.replace(/0+$/, "");
    return s.endsWith(".") ? s.slice(0, -1) : s;
  };
  const parts = payments.flatMap((p, i) => {
    const k = (n: string) => (i === 0 ? n : `${n}.${i}`);
    const q = [`${k("address")}=${p.to}`, `${k("amount")}=${zec(p.amount_zat)}`];
    if (p.memo) q.push(`${k("memo")}=${Buffer.from(p.memo).toString("base64url")}`);
    return q;
  });
  return `zcash:?${parts.join("&")}`;
}

/**
 * Build a PCZT that pays every payment and leaves nothing in the escrow. The fixed payments
 * (marketplace fee) get their exact amount; the first payment (the winner) gets the rest minus
 * the network fee. `zcash-devtool pczt create` (patched to take a ZIP 321 request, see
 * scripts/zcash-devtool-payment-uri.patch) adds a change output for any excess, so try network
 * fees from the lowest upward: the first one the wallet accepts is the ZIP 317 conventional fee,
 * and change is zero. The signers refuse change, and any fee that is not exactly ZIP 317's.
 */
function createSplitPczt(w: string, payments: Payment[], memo: string, out: string): number {
  const total = balance(w).total;
  const fixed = payments.slice(1).reduce((s, p) => s + p.min_amount_zat, 0);
  let last: unknown;
  for (let fee = 10_000; fee <= FEE_ALLOWANCE_ZAT; fee += 5_000) {
    const uri = zip321Uri([
      { to: payments[0].to, amount_zat: total - fixed - fee, memo },
      ...payments.slice(1).map((p) => ({ to: p.to, amount_zat: p.min_amount_zat, memo: `${memo} ${p.party} fee` })),
    ]);
    try {
      devtool(["pczt", "-w", w, "create", "--payment-uri", uri, "--output", out]);
      say(`  PCZT pays ${payments.length} outputs, network fee ${fee} zat`);
      return fee;
    } catch (e) {
      if (!/insufficient/i.test(String(e))) throw e;
      last = e;
    }
  }
  throw new Error(`no network fee up to ${FEE_ALLOWANCE_ZAT} zat fits: ${last}`);
}

async function payout(job: Job, payments: Payment[], memo: string, signers: [Party, Party], arbiterGate?: (s: string) => void) {
  const w = join(jobDir(job.id), "wallet");
  balance(w);
  const tag = signers.join("-");
  const pczt = join(jobDir(job.id), `payout-${tag}.pczt`);
  const proven = join(jobDir(job.id), `payout-${tag}.proven.pczt`);
  if (payments.length === 1) devtool(["pczt", "-w", w, "create-max", "--address", payments[0].to, "--memo", memo, "--output", pczt]);
  else createSplitPczt(w, payments, memo, pczt);
  const t0 = Date.now();
  devtool(["pczt", "-w", w, "prove", pczt, "--output", proven]);
  say(`  Halo 2 proof built in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
  const signed = await frostSign(job, signers, proven, expectFromPayments(payments, memo), arbiterGate);
  const out = devtool(["pczt", "-w", w, "send", "-s", LIGHTWALLETD, signed]);
  const txid = out.trim().split("\n").pop()!;
  let height: number | undefined;
  if (TESTNET) {
    say(`  payout tx ${txid} broadcast`);
    await waitChain("the payout to be mined", () => { const b = balance(w); height = minedHeight(w, txid); return { ok: height !== undefined, tip: b.tip }; });
    say(`  payout mined at height ${height}`);
  } else {
    await mine(10);
    await waitIndexer();
  }
  const left = balance(w);
  if (left.total !== 0) throw new Error(`escrow still holds ${left.total} zat after payout`);
  return { txid, height };
}

/** Happy path: buyer is satisfied; buyer + seller sign the payout to the seller. No arbiter involved. */
export async function release(id: string): Promise<Job> {
  const job = loadJob(id);
  if (job.state !== "funded") throw new Error(`job ${id} is ${job.state}`);
  say(`== job ${id}: release (buyer + seller co-sign, arbiter not involved)`);
  // Buyer and seller each check the outputs against the terms they agreed (fee included).
  const payments = splitPayout(job.terms, job.funded_zat ?? job.terms.price_zat, "seller");
  ({ txid: job.payout_txid, height: job.payout_height } = await payout(job, payments, `zescrow release ${id}`, ["buyer", "seller"]));
  job.state = "released";
  saveJob(job);
  say(`  paid seller: tx ${job.payout_txid}`);
  return job;
}

// ---------- disputes ----------

export function submitEvidence(id: string, party: "buyer" | "seller", kind: string, note: string, bytes: Buffer, at = new Date()) {
  const item: EvidenceItem = { party, kind, note, sha256: sha256(bytes), submitted_at: at.toISOString() };
  const dir = join(jobDir(id), "evidence");
  mkdirSync(dir, { recursive: true });
  const n = readdirSync(dir).filter((f) => f.endsWith(".json")).length;
  writeJson(join(dir, `${n}-${party}-${kind}.json`), item);
  say(`  ${party} submitted evidence "${kind}" sha256 ${item.sha256.slice(0, 16)}…`);
  return item;
}

/** The arbiter (Predge) reviews evidence and issues a signed verdict. It moves no funds. */
export function issueVerdict(id: string): SignedVerdict {
  const job = loadJob(id);
  const arb = loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));
  const dir = join(jobDir(id), "evidence");
  const evidence = existsSync(dir) ? readdirSync(dir).sort().map((f) => readJson<EvidenceItem>(join(dir, f))) : [];
  const { decision, reasons } = adjudicate(job.terms, evidence);
  const toSeller = decision === "release_to_seller";
  const v: Verdict = {
    schema: "predge.zescrow.verdict/1",
    job_id: id,
    escrow_address: job.escrow_address,
    group_ak: job.group_ak,
    terms_sha256: job.terms_sha256,
    decision,
    reasons,
    evidence,
    payout: {
      to: toSeller ? job.terms.seller_payout_address : job.terms.buyer_refund_address,
      party: toSeller ? "seller" : "buyer",
      min_amount_zat: (job.funded_zat ?? job.terms.price_zat) - FEE_ALLOWANCE_ZAT,
    },
    cosigner_with: toSeller ? "seller" : "buyer",
    issued_at: new Date().toISOString(),
    arbiter_pubkey: arb.pubHex,
  };
  const sv = signVerdict(v, arb);
  writeJson(join(jobDir(id), "verdict.json"), sv);
  say(`== job ${id}: Predge verdict ${decision} (Ed25519 ${sv.signature.slice(0, 16)}…)`);
  for (const r of reasons) say(`  - ${r}`);
  return sv;
}

/** The winner and the arbiter co-sign exactly the payout the verdict names. */
export async function enforceVerdict(id: string): Promise<Job> {
  const job = loadJob(id);
  if (job.state !== "funded") throw new Error(`job ${id} is ${job.state}`);
  const sv = readJson<SignedVerdict>(join(jobDir(id), "verdict.json"));
  const arb = loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));
  if (!verifyVerdict(sv, arb.pubHex)) throw new Error("verdict signature invalid");
  if (sv.verdict.job_id !== id || sv.verdict.escrow_address !== job.escrow_address) throw new Error("verdict is for another escrow");
  const vhash = sha256(canonical(sv));
  say(`== job ${id}: ${sv.verdict.cosigner_with} + arbiter co-sign the payout named in the verdict`);
  // The arbiter signs only this verdict's payout: `sign-pczt` checks payee, amount, fee and that the
  // payout memo carries this verdict's hash. The gate records what it signed.
  const gate = (sighash: string) => {
    writeJson(join(jobDir(id), "arbiter-cosign.json"), { verdict_sha256: vhash, sighash, at: new Date().toISOString() });
  };
  ({ txid: job.payout_txid, height: job.payout_height } =
    await payout(job, verdictPayments(sv.verdict), `zescrow verdict ${vhash.slice(0, 32)}`, [sv.verdict.cosigner_with, "arbiter"], gate));
  job.state = sv.verdict.decision === "release_to_seller" ? "released" : "refunded";
  job.verdict_sha256 = vhash;
  saveJob(job);
  say(`  paid ${verdictPayments(sv.verdict).map((p) => p.party).join(" + ")}: tx ${job.payout_txid}`);
  return job;
}

export function arbiterRefusesWrongPayout(id: string): Promise<string> {
  // Used by the demo to show the arbiter cannot be talked into a payout the verdict didn't name.
  const job = loadJob(id);
  const sv = readJson<SignedVerdict>(join(jobDir(id), "verdict.json"));
  const wrong = verdictPayments(sv.verdict)[0].party === "buyer" ? job.terms.seller_payout_address : job.terms.buyer_refund_address;
  const w = join(jobDir(id), "wallet");
  const pczt = join(jobDir(id), "wrong.pczt");
  devtool(["pczt", "-w", w, "create-max", "--address", wrong, "--output", pczt], { quiet: true });
  devtool(["pczt", "-w", w, "prove", pczt, "--output", pczt + ".proven"], { quiet: true });
  const vhash = sha256(canonical(sv));
  return Promise.resolve()
    .then(() => checkPayout(pczt + ".proven", expectFromPayments(verdictPayments(sv.verdict), `zescrow verdict ${vhash.slice(0, 32)}`)))
    .then(() => "arbiter signed (unexpected)")
    .catch((e: Error) => `arbiter refuses: ${e.message}`);
}

/**
 * Used by the fee demo: someone builds a release that pays the whole escrow to the seller and
 * skips the marketplace fee output. The buyer's check (the same `zescrow-frost` check it signs
 * through) refuses it, because it does not match the fee fixed in the terms.
 */
export function signersRefuseMissingFee(id: string): Promise<string> {
  const job = loadJob(id);
  const w = join(jobDir(id), "wallet");
  const pczt = join(jobDir(id), "nofee.pczt");
  const memo = `zescrow release ${id}`;
  devtool(["pczt", "-w", w, "create-max", "--address", job.terms.seller_payout_address, "--memo", memo, "--output", pczt], { quiet: true });
  devtool(["pczt", "-w", w, "prove", pczt, "--output", pczt + ".proven"], { quiet: true });
  const expect = expectFromPayments(splitPayout(job.terms, job.funded_zat ?? job.terms.price_zat, "seller"), memo);
  return Promise.resolve()
    .then(() => checkPayout(pczt + ".proven", expect))
    .then(() => "buyer signed (unexpected)")
    .catch((e: Error) => `buyer refuses: ${e.message}`);
}

export type { Decision };
