// Thin wrappers over the external tools. Every Zcash and FROST operation is done by:
//   zcash-devtool  (ECC/zcash): wallets, PCZT create/prove/send, light-client sync
//   zcash-sign     (ZF frost-tools): PCZT sighash + randomizer extraction, signature injection
//   zescrow-frost  (this repo, over ZF reddsa/frost-rerandomized): per-party FROST rounds
//   zebrad         (ZF): regtest validator, block mining via the `generate` RPC
// ZESCROW_NETWORK=test runs the same protocol on the public Zcash testnet (via the zecrocks
// lightwalletd); there is no mining there, so the app waits for real blocks instead.

import { spawn, spawnSync } from "node:child_process";
import { resolve } from "node:path";

export const ROOT = resolve(import.meta.dirname, "../..");
export const DEPS = process.env.ZESCROW_DEPS ?? resolve(ROOT, "../predge-zcash-escrow-deps");
export const BIN = {
  devtool: process.env.ZCASH_DEVTOOL ?? `${DEPS}/zcash-devtool/target/release/zcash-devtool`,
  zcashSign: process.env.ZCASH_SIGN ?? `${DEPS}/frost-tools/target/release/zcash-sign`,
  // `zcash-sign sign` must know the chain's consensus branch id. The pinned build stops at NU6.3,
  // which is enough for regtest; testnet runs NU7, so sign there with the NU7 build
  // (scripts/build-deps.sh --testnet). `generate` always uses the pinned build.
  zcashSignPczt: process.env.ZCASH_SIGN_PCZT ??
    (process.env.ZESCROW_NETWORK === "test" || process.env.ZESCROW_NETWORK === "main" ? `${DEPS}/frost-tools-nu7/target/release/zcash-sign` : process.env.ZCASH_SIGN ?? `${DEPS}/frost-tools/target/release/zcash-sign`),
  frost: process.env.ZESCROW_FROST ?? `${ROOT}/crates/zescrow-frost/target/release/zescrow-frost`,
};
// ZESCROW_NETWORK=main runs the same code on Zcash mainnet with real ZEC (small amounts only).
export const NETWORK: "regtest" | "test" | "main" =
  process.env.ZESCROW_NETWORK === "main" ? "main" : process.env.ZESCROW_NETWORK === "test" ? "test" : "regtest";
/** True on any public network (testnet or mainnet): real blocks, no mining, pre-funded buyer. */
export const TESTNET = NETWORK !== "regtest";
export const MAINNET = NETWORK === "main";
/** Network name for zcash-sign / zcash-devtool (regtest keys are encoded as test, then re-encoded). */
export const NET = MAINNET ? "main" : "test";
export const LIGHTWALLETD = process.env.LIGHTWALLETD ?? (TESTNET ? "zecrocks" : "localhost:8137");
export const ZEBRA_RPC = process.env.ZEBRA_RPC ?? "http://127.0.0.1:18232";

export type Logger = (line: string) => void;
let log: Logger = (l) => console.log(l);
export const setLogger = (l: Logger) => (log = l);
export const say = (l: string) => log(l);

export function run(bin: string, args: string[], opts: { input?: string; quiet?: boolean } = {}): string {
  const short = bin.split("/").pop();
  if (!opts.quiet) log(`  $ ${short} ${args.map((a) => (a.length > 70 ? a.slice(0, 24) + "…" + a.slice(-12) : a)).join(" ")}`);
  const r = spawnSync(bin, args, { input: opts.input, encoding: "utf8", maxBuffer: 64 << 20, env: { ...process.env, RUST_LOG: "error" } });
  if (r.status !== 0) {
    throw new Error(`${short} ${args.slice(0, 3).join(" ")} failed (${r.status}):\n${r.stderr || r.stdout}`);
  }
  return r.stdout;
}

export const devtool = (args: string[], opts?: { quiet?: boolean }) => run(BIN.devtool, args, opts);
export const frost = (args: string[]) => run(BIN.frost, args, { quiet: true });

export async function rpc<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
  const res = await fetch(ZEBRA_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = (await res.json()) as { result?: T; error?: { message: string } };
  if (j.error) throw new Error(`zebra ${method}: ${j.error.message}`);
  return j.result as T;
}

export async function mine(n: number): Promise<number> {
  if (TESTNET) throw new Error("mine() is regtest only");
  await rpc("generate", [n]);
  const height = await rpc<number>("getblockcount");
  log(`  mined ${n} block(s), tip ${height}`);
  return height;
}

/**
 * Drive `zcash-sign sign` (ZF frost-tools), which prints the sighash and one randomizer per
 * spend, then reads one hex signature per spend from stdin. `signer` turns
 * (sighash, randomizer) into a 64-byte RedPallas signature via 2-of-3 FROST.
 */
export function zcashSign(
  inPczt: string,
  outPczt: string,
  signer: (sighash: string, randomizers: { index: number; pool: string; alpha: string }[]) => Promise<string[]>,
): Promise<{ sighash: string; spends: number }> {
  return new Promise((resolveP, reject) => {
    log(`  $ zcash-sign sign -i ${inPczt.split("/").pop()} -o ${outPczt.split("/").pop()}`);
    const p = spawn(BIN.zcashSignPczt, ["sign", "-i", inPczt, "-o", outPczt, "-n", NET], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let started = false;
    p.stderr.on("data", (d) => (err += d));
    p.stdout.on("data", async (d) => {
      out += d;
      if (started || !out.includes("Input hex-encoded signature")) return;
      started = true;
      try {
        const sighash = /SIGHASH: ([0-9a-f]{64})/.exec(out)?.[1];
        if (!sighash) throw new Error("zcash-sign printed no sighash");
        const rands = [...out.matchAll(/Randomizer #(\d+) \((\w+)\): ([0-9a-f]{64})/g)].map((m) => ({
          index: Number(m[1]),
          pool: m[2],
          alpha: m[3],
        }));
        const sigs = await signer(sighash, rands);
        p.stdin.end(sigs.join("\n") + "\n");
        p.on("close", (code) => {
          if (code !== 0) reject(new Error(`zcash-sign exited ${code}: ${err}${out}`));
          else resolveP({ sighash, spends: rands.length });
        });
      } catch (e) {
        p.kill();
        reject(e);
      }
    });
    p.on("error", reject);
    // e.g. an unknown consensus branch id: zcash-sign exits before asking for signatures.
    p.on("close", (code) => { if (!started) reject(new Error(`zcash-sign exited ${code}: ${err}${out}`)); });
  });
}
