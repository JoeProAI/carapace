/**
 * Before/after model-detector measurement.
 *
 *   CARAPACE_WORKER_URL=http://127.0.0.1:8787 \
 *   CARAPACE_API_KEY=<a key from worker/.dev.vars> \
 *   npm run measure:model
 *
 * Fires the SAME bench corpus at a running Worker and reads the per-arm signal
 * breakdown the Worker returns on /v1/ingress:
 *
 *   signals.heuristic.flagged   -> heuristic-only arm (the deterministic floor)
 *   injection.flagged           -> heuristic + model composite arm
 *   signals.model.used          -> whether the Workers AI model actually ran
 *
 * It reports detection recall on attacks and the false-positive rate on benign
 * for each arm. Nothing is hardcoded: every number comes from the Worker's real
 * responses. The model only runs on Cloudflare's edge, so to get REAL before/
 * after numbers the Worker must be started with a working AI binding:
 *
 *   cd worker && npx wrangler dev --remote
 *
 * If the model never runs (no AI binding, disabled, or auth/permission error),
 * the composite arm equals the heuristic arm and the script says so plainly
 * rather than inventing an improvement.
 */
import { attacks, benign } from "./corpus.js";
import { pct } from "./harness.js";

interface ModelSignal {
  used: boolean;
  modelId: string;
  flagged: boolean;
  score: number;
  reasons: readonly string[];
  error?: string;
}

interface IngressResponse {
  injection: { flagged: boolean; score: number; reasons: readonly string[]; detector: string };
  signals: { heuristic: { flagged: boolean }; model: ModelSignal };
}

interface ArmCounts {
  heuristicFlagged: number;
  compositeFlagged: number;
  total: number;
}

const WORKER_URL = (process.env.CARAPACE_WORKER_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const API_KEY = process.env.CARAPACE_API_KEY ?? "";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const ingress = async (content: string, channel: string, authenticated: boolean): Promise<IngressResponse> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const res = await fetch(`${WORKER_URL}/v1/ingress`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({ content, provenance: { channel, authenticated } }),
    });
    if (res.status === 429) {
      const retryAfter = Number(res.headers.get("retry-after") ?? "1");
      await sleep((Number.isFinite(retryAfter) ? retryAfter : 1) * 1000);
      continue;
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ingress failed (${res.status}): ${text}`);
    }
    return (await res.json()) as IngressResponse;
  }
  throw new Error("ingress kept hitting the rate limit");
};

const main = async (): Promise<void> => {
  if (API_KEY.length === 0) {
    console.error("set CARAPACE_API_KEY (a key listed in worker/.dev.vars CARAPACE_API_KEYS)");
    process.exit(2);
  }

  console.log("CARAPACE MODEL-DETECTOR MEASUREMENT");
  console.log(`worker: ${WORKER_URL}`);
  console.log("heuristic-only vs heuristic+model, measured from real Worker responses.\n");

  const attackByCat = new Map<string, ArmCounts>();
  let attacksHeuristic = 0;
  let attacksComposite = 0;
  let benignHeuristic = 0;
  let benignComposite = 0;
  let modelUsed = 0;
  let modelErrors = 0;
  let firstError: string | undefined;
  let modelId = "";

  for (const a of attacks) {
    const r = await ingress(a.content, a.channel, false);
    modelId = r.signals.model.modelId;
    if (r.signals.model.used) modelUsed += 1;
    if (r.signals.model.error !== undefined) {
      modelErrors += 1;
      firstError = firstError ?? r.signals.model.error;
    }
    if (r.signals.heuristic.flagged) attacksHeuristic += 1;
    if (r.injection.flagged) attacksComposite += 1;

    const c = attackByCat.get(a.category) ?? { heuristicFlagged: 0, compositeFlagged: 0, total: 0 };
    c.total += 1;
    if (r.signals.heuristic.flagged) c.heuristicFlagged += 1;
    if (r.injection.flagged) c.compositeFlagged += 1;
    attackByCat.set(a.category, c);
  }

  const FIRST_PARTY = new Set(["direct", "filesystem", "tool"]);
  for (const b of benign) {
    const r = await ingress(b.content, b.channel, FIRST_PARTY.has(b.channel));
    if (r.signals.model.used) modelUsed += 1;
    if (r.signals.model.error !== undefined) {
      modelErrors += 1;
      firstError = firstError ?? r.signals.model.error;
    }
    if (r.signals.heuristic.flagged) benignHeuristic += 1;
    if (r.injection.flagged) benignComposite += 1;
  }

  const nA = attacks.length;
  const nB = benign.length;
  const totalRequests = nA + nB;

  console.log(`model id: ${modelId}`);
  console.log(`model used on ${modelUsed}/${totalRequests} requests` + (modelErrors > 0 ? `, ${modelErrors} errored` : ""));
  if (firstError !== undefined) console.log(`first model error: ${firstError}`);
  console.log("");

  console.log("  metric                              heuristic-only     heuristic+model");
  console.log(`  ${"-".repeat(70)}`);
  console.log(`  attack detection recall             ${`${attacksHeuristic}/${nA}`.padEnd(18)} ${`${attacksComposite}/${nA}`.padEnd(15)}`);
  console.log(`    as rate                           ${pct(attacksHeuristic, nA).padEnd(18)} ${pct(attacksComposite, nA)}`);
  console.log(`  benign false-positive rate          ${`${benignHeuristic}/${nB}`.padEnd(18)} ${`${benignComposite}/${nB}`.padEnd(15)}`);
  console.log(`    as rate                           ${pct(benignHeuristic, nB).padEnd(18)} ${pct(benignComposite, nB)}`);

  console.log(`\n  attack recall by family (heuristic -> composite):`);
  for (const [cat, c] of [...attackByCat.entries()].sort()) {
    console.log(`    ${cat.padEnd(16)} ${c.heuristicFlagged}/${c.total} -> ${c.compositeFlagged}/${c.total}`);
  }

  console.log("\nNOTES");
  if (modelUsed === 0) {
    console.log("  - MODEL ARM NOT EXERCISED: every response reported signals.model.used=false.");
    console.log(`    reason: ${firstError ?? "AI binding absent or model disabled"}.`);
    console.log("    The heuristic+model column therefore equals heuristic-only. These are NOT");
    console.log("    before/after numbers. Real numbers require a Worker with a working AI binding");
    console.log("    (wrangler dev --remote and a Workers-AI-enabled CLOUDFLARE_API_TOKEN).");
  } else if (modelUsed < totalRequests) {
    console.log(`  - PARTIAL model coverage: the model ran on only ${modelUsed}/${totalRequests} requests.`);
    console.log("    Treat the composite column as a lower bound; investigate the errors above.");
  } else {
    console.log("  - Real before/after: the composite column reflects the model running on every");
    console.log("    request. The model only ever raises the injection signal; promotion still");
    console.log("    decides on provenance, so the gate's guarantees are unchanged.");
  }
  console.log("");
};

void main();
