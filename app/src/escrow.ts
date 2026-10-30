// The escrow protocol, end to end, on top of existing Zcash tooling.
//
// Roles and what each one holds (one directory per party under .state/parties):
//   buyer   : own zcash-devtool wallet (seed) + its FROST share for each job
//   seller  : own zcash-devtool wallet (seed) + its FROST share for each job
//   arbiter : its FROST share for each job + an Ed25519 verdict key. No wallet, no seed.
// The escrow address itself is a FROST group key: 2 of {buyer, seller, arbiter} must sign.
// The coordinator (this process) only relays public round messages and PCZTs; it holds no secret.

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { BIN, LIGHTWALLETD, ROOT, devtool, frost, mine, rpc, say, zcashSign } from "./tools.ts";
import {
  adjudicate, canonical, loadArbiterKey, sha256, signVerdict, verifyVerdict,
  type Decision, type EvidenceItem, type SignedVerdict, type Terms, type Verdict,
} from "./verdict.ts";

export const STATE = process.env.ZESCROW_STATE ?? join(ROOT, ".state");
const HEIGHTS = join(ROOT, "chain/activation-heights.toml");
const COMPOSE = join(ROOT, "chain/compose.yaml");
const FEE_ALLOWANCE_ZAT = 20_000; // ZIP 317: 2 logical actions x 5,000 zat today, with headroom

type Party = "buyer" | "seller" | "arbiter";
const partyDir = (p: Party) => join(STATE, "parties", p);
const walletDir = (p: "buyer" | "seller") => join(partyDir(p), "wallet");
const ageFile = (p: "buyer" | "seller") => join(partyDir(p), "wallet.age");
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
  state: "created" | "funded" | "released" | "refunded";
  payout_txid?: string;
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

/** zcash-devtool's view-only import writes its built-in regtest heights; make them match the chain. */
function pinHeights(dir: string) {
  const cfg = join(dir, "keys.toml");
  const heights = readFileSync(HEIGHTS, "utf8");
  const nu7 = /^nu7 = (.*)$/m.exec(heights)?.[1] ?? '"never"';
  writeFileSync(cfg, readFileSync(cfg, "utf8").replace(/^nu7 = .*$/m, `nu7 = ${nu7}`));
}

export function partyAddress(p: "buyer" | "seller"): string {
  return orchardAddress(walletDir(p));
}

/** One-time: party wallets, arbiter verdict key, and point Zebra's coinbase at the buyer. */
export async function setup(): Promise<void> {
  say("== setup: party wallets and arbiter key");
  for (const p of ["buyer", "seller"] as const) {
    if (existsSync(join(walletDir(p), "keys.toml"))) continue;
    mkdirSync(partyDir(p), { recursive: true });
    devtool(["wallet", "-w", walletDir(p), "init", "--name", p, "-i", ageFile(p), "-n", "regtest",
      "--activation-heights", HEIGHTS, "-s", LIGHTWALLETD]);
  }
  const arb = loadArbiterKey(join(partyDir("arbiter"), "verdict-ed25519.pem"));
  say(`  arbiter verdict key ${arb.pubHex}`);
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

export const fmt = (zat: number) => `${(zat / 1e8).toFixed(8)} ZEC`;

// ---------- job lifecycle ----------

/** Seller lists an item (commits to its hash); a fresh 2-of-3 FROST escrow is created for the job. */
export function createJob(id: string, item: { name: string; bytes: Buffer; price_zat: number; deliver_in_s?: number }): Job {
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
  const gen = spawnSync(BIN.zcashSign, ["generate", "--ak", ak, "-n", "test"], { encoding: "utf8" });
  if (gen.status !== 0) throw new Error(gen.stderr);
  const ua = /address: "(\S+)"/.exec(gen.stdout)![1];
  const ufvk = /Viewing Key: "(\S+)"/.exec(gen.stdout)![1];
  const job: Job = {
    id, terms, terms_sha256: sha256(canonical(terms)), group_ak: ak, state: "created",
    escrow_address: frost(["reencode", "--value", ua, "--network", "regtest"]).trim(),
    escrow_ufvk: frost(["reencode", "--value", ufvk, "--network", "regtest"]).trim(),
  };
  const w = join(jobDir(id), "wallet");
  devtool(["wallet", "-w", w, "init-fvk", "--name", `escrow-${id}`, "--fvk", job.escrow_ufvk, "-s", LIGHTWALLETD], { quiet: true });
  pinHeights(w);
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
  await mine(10);
  await waitIndexer();
  const b = balance(join(jobDir(id), "wallet"));
  if (b.ironwood < job.terms.price_zat) throw new Error(`escrow shows ${b.ironwood} zat, expected ${job.terms.price_zat}`);
  job.funded_zat = b.ironwood;
  job.state = "funded";
  saveJob(job);
  say(`  escrow holds ${fmt(b.ironwood)} in the Ironwood pool (tx ${job.fund_txid?.slice(0, 16)}…)`);
  return job;
}

// ---------- payout: PCZT + 2-of-3 FROST ----------

interface PcztOutput { value: number; to?: string }

/** Parse non-dummy outputs from `zcash-devtool pczt inspect`. */
function pcztOutputs(pczt: string): PcztOutput[] {
  const txt = devtool(["pczt", "inspect", pczt], { quiet: true });
  return [...txt.matchAll(/Output: (\d+) zatoshis(?: to (\S+))?/g)].map((m) => ({ value: Number(m[1]), to: m[2] }));
}

/** Independently recompute the sighash and randomizers of a PCZT with ZF zcash-sign. */
function pcztSighash(pczt: string): Promise<{ sighash: string; alphas: string[] }> {
  return new Promise((res, rej) => {
    const p = spawn(BIN.zcashSign, ["sign", "-i", pczt, "-o", "/dev/null", "-n", "test"]);
    let out = "";
    p.stdout.on("data", (d) => {
      out += d;
      if (out.includes("Input hex-encoded signature")) {
        p.kill();
        res({ sighash: /SIGHASH: ([0-9a-f]{64})/.exec(out)![1], alphas: [...out.matchAll(/Randomizer #\d+ \(\w+\): ([0-9a-f]{64})/g)].map((m) => m[1]) });
      }
    });
    p.on("close", () => { if (!out.includes("Input hex")) rej(new Error(`zcash-sign: ${out}`)); });
  });
}

/**
 * Each signer's own check before releasing a FROST share: the PCZT must pay `expect.to` at least
 * `expect.min` and nothing to anyone else; the message must be that PCZT's real sighash.
 */
async function approve(party: Party, pczt: string, expect: { to: string; min: number }, message: string, alpha: string) {
  const outs = pcztOutputs(pczt).filter((o) => o.value > 0);
  const paid = outs.filter((o) => o.to === expect.to).reduce((s, o) => s + o.value, 0);
  const others = outs.filter((o) => o.to !== expect.to);
  if (paid < expect.min) throw new Error(`${party} refuses: PCZT pays ${paid} zat to the agreed address, expected >= ${expect.min}`);
  if (others.length) throw new Error(`${party} refuses: PCZT has outputs to other addresses`);
  const own = await pcztSighash(pczt);
  if (own.sighash !== message || !own.alphas.includes(alpha)) throw new Error(`${party} refuses: message is not this PCZT's sighash`);
}

async function frostSign(job: Job, signers: [Party, Party], pczt: string, expect: { to: string; min: number },
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
      // Round 2: each signer checks the transaction itself, then signs.
      for (const p of signers) {
        await approve(p, pczt, expect, sighash, r.alpha);
        if (p === "arbiter") arbiterGate?.(sighash);
        frost(["sign", "--key", shareFile(p, job.id), "--nonces", join(partyDir(p), "nonces", `${job.id}-${r.index}.json`),
          "--package", pkg, "--randomizer", r.alpha, "--out", join(dir, `${p}-${r.index}.share.json`)]);
        say(`  ${p} checked the PCZT and produced a signature share`);
      }
      sigs.push(frost(["aggregate", "--group", group, "--package", pkg, "--randomizer", r.alpha,
        "--shares", ...signers.map((p) => join(dir, `${p}-${r.index}.share.json`))]).trim());
    }
    say("  aggregated a RedPallas spend-auth signature (verified against the rerandomized key)");
    return sigs;
  });
  return signed;
}

async function payout(job: Job, to: string, memo: string, signers: [Party, Party], arbiterGate?: (s: string) => void) {
  const w = join(jobDir(job.id), "wallet");
  balance(w);
  const tag = signers.join("-");
  const pczt = join(jobDir(job.id), `payout-${tag}.pczt`);
  const proven = join(jobDir(job.id), `payout-${tag}.proven.pczt`);
  devtool(["pczt", "-w", w, "create-max", "--address", to, "--memo", memo, "--output", pczt]);
  const t0 = Date.now();
  devtool(["pczt", "-w", w, "prove", pczt, "--output", proven]);
  say(`  Halo 2 proof built in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
  const signed = await frostSign(job, signers, proven, { to, min: (job.funded_zat ?? job.terms.price_zat) - FEE_ALLOWANCE_ZAT }, arbiterGate);
  const out = devtool(["pczt", "-w", w, "send", "-s", LIGHTWALLETD, signed]);
  const txid = out.trim().split("\n").pop()!;
  await mine(10);
  await waitIndexer();
  const left = balance(w);
  if (left.total !== 0) throw new Error(`escrow still holds ${left.total} zat after payout`);
  return txid;
}

/** Happy path: buyer is satisfied; buyer + seller sign the payout to the seller. No arbiter involved. */
export async function release(id: string): Promise<Job> {
  const job = loadJob(id);
  if (job.state !== "funded") throw new Error(`job ${id} is ${job.state}`);
  say(`== job ${id}: release (buyer + seller co-sign, arbiter not involved)`);
  job.payout_txid = await payout(job, job.terms.seller_payout_address, `zescrow release ${id}`, ["buyer", "seller"]);
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
  // The arbiter's gate: it signs only for this verdict's payout (approve() checks outputs + sighash).
  const gate = (sighash: string) => {
    writeJson(join(jobDir(id), "arbiter-cosign.json"), { verdict_sha256: vhash, sighash, at: new Date().toISOString() });
  };
  job.payout_txid = await payout(job, sv.verdict.payout.to, `zescrow verdict ${vhash.slice(0, 32)}`, [sv.verdict.cosigner_with, "arbiter"], gate);
  job.state = sv.verdict.decision === "release_to_seller" ? "released" : "refunded";
  job.verdict_sha256 = vhash;
  saveJob(job);
  say(`  paid ${sv.verdict.payout.party}: tx ${job.payout_txid}`);
  return job;
}

export function arbiterRefusesWrongPayout(id: string): Promise<string> {
  // Used by the demo to show the arbiter cannot be talked into a payout the verdict didn't name.
  const job = loadJob(id);
  const sv = readJson<SignedVerdict>(join(jobDir(id), "verdict.json"));
  const wrong = sv.verdict.payout.party === "buyer" ? job.terms.seller_payout_address : job.terms.buyer_refund_address;
  const w = join(jobDir(id), "wallet");
  const pczt = join(jobDir(id), "wrong.pczt");
  devtool(["pczt", "-w", w, "create-max", "--address", wrong, "--output", pczt], { quiet: true });
  devtool(["pczt", "-w", w, "prove", pczt, "--output", pczt + ".proven"], { quiet: true });
  return approve("arbiter", pczt + ".proven", { to: sv.verdict.payout.to, min: sv.verdict.payout.min_amount_zat }, "", "")
    .then(() => "arbiter signed (unexpected)")
    .catch((e: Error) => e.message);
}

export type { Decision };
