// Demo UI server (localhost only). The page drives the same functions the CLI uses and streams
// the tool log, so what the audience sees is the real chain, wallets and FROST rounds.
import { createServer, type ServerResponse } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  STATE, balance, createJob, enforceVerdict, fund, issueVerdict, listJobs, loadJob, release, setup, submitEvidence,
} from "./escrow.ts";
import { ROOT, setLogger } from "./tools.ts";
import { verifyVerdict, type SignedVerdict } from "./verdict.ts";

const PORT = Number(process.env.PORT ?? 4747);
const clients = new Set<ServerResponse>();
const history: string[] = [];
setLogger((line) => {
  console.log(line);
  history.push(line);
  if (history.length > 400) history.shift();
  for (const c of clients) c.write(`data: ${JSON.stringify(line)}\n\n`);
});

let busy = false;
const ZEC = 100_000_000;

async function act(action: string, job?: string) {
  switch (action) {
    case "setup":
      return setup();
    case "new": {
      await setup();
      const id = `J-${Date.now().toString(36)}`;
      const bytes = Buffer.from(`deliverable for ${id}`);
      createJob(id, { name: "Logo pack (digital goods)", bytes, price_zat: 1 * ZEC });
      return fund(id);
    }
    case "release": {
      const j = loadJob(job!);
      submitEvidence(j.id, "seller", "delivery", "sent the file", Buffer.from(`deliverable for ${j.id}`));
      return release(j.id);
    }
    case "dispute-buyer": {
      submitEvidence(job!, "buyer", "complaint", "nothing usable delivered", Buffer.from(`complaint ${job}`));
      submitEvidence(job!, "seller", "delivery", "sent a draft", Buffer.from(`draft ${job}`));
      issueVerdict(job!);
      return enforceVerdict(job!);
    }
    case "dispute-seller": {
      const bytes = Buffer.from(`deliverable for ${job}`);
      submitEvidence(job!, "seller", "delivery", "sent the file", bytes);
      submitEvidence(job!, "buyer", "complaint", "not what I ordered", Buffer.from(`complaint ${job}`));
      submitEvidence(job!, "buyer", "received_file", "file I got", bytes);
      issueVerdict(job!);
      return enforceVerdict(job!);
    }
    default:
      throw new Error(`unknown action ${action}`);
  }
}

function state() {
  const wallets: Record<string, number | null> = {};
  for (const p of ["buyer", "seller"]) {
    const dir = join(STATE, "parties", p, "wallet");
    wallets[p] = existsSync(join(dir, "keys.toml")) ? balance(dir).total : null;
  }
  const jobs = listJobs().map((j) => {
    const vp = join(STATE, "jobs", j.id, "verdict.json");
    const verdict = existsSync(vp) ? (JSON.parse(readFileSync(vp, "utf8")) as SignedVerdict) : undefined;
    return { ...j, escrow_ufvk: undefined, verdict, verdict_valid: verdict ? verifyVerdict(verdict) : undefined };
  });
  return { wallets, jobs, busy };
}

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(readFileSync(join(ROOT, "app/ui/index.html")));
    }
    if (url.pathname === "/api/state") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify(busy ? { busy, jobs: listJobs().map((j) => ({ ...j, escrow_ufvk: undefined })), wallets: {} } : state()));
    }
    if (url.pathname === "/api/log") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      for (const l of history) res.write(`data: ${JSON.stringify(l)}\n\n`);
      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }
    if (url.pathname === "/api/run" && req.method === "POST") {
      if (busy) { res.writeHead(409); return res.end("busy"); }
      busy = true;
      res.writeHead(202);
      res.end();
      act(url.searchParams.get("action") ?? "", url.searchParams.get("job") ?? undefined)
        .catch((e: Error) => history.push(`ERROR ${e.message}`) && clients.forEach((c) => c.write(`data: ${JSON.stringify(`ERROR ${e.message}`)}\n\n`)))
        .finally(() => { busy = false; clients.forEach((c) => c.write(`data: ${JSON.stringify("__done__")}\n\n`)); });
      return;
    }
    res.writeHead(404);
    res.end();
  } catch (e) {
    res.writeHead(500);
    res.end(String(e));
  }
}).listen(PORT, "127.0.0.1", () => console.log(`zescrow UI on http://127.0.0.1:${PORT}`));
