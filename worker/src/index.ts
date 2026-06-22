/**
 * Carapace as a hosted service: a thin Cloudflare Worker that wraps the exact
 * same firewall as the npm library, so an agent can protect its memory writes
 * by calling a URL with an API key instead of installing anything.
 *
 * Endpoints (all JSON):
 *   GET  /health
 *   POST /v1/ingress          { content, provenance }            -> envelope summary
 *   POST /v1/promote          { content, provenance, target?, corroboration?, touchesIdentity? } -> decision
 *   GET  /v1/ledger/head      -> { head, count }
 *   GET  /v1/ledger/verify    -> { valid, count }
 *
 * The hash-chained audit ledger lives in a per-tenant Durable Object so it is
 * append-only and strongly consistent. The detector heuristics and provenance
 * gate are the real ones from ../src; nothing here re-implements security.
 *
 * Trust model for a hosted surface: the service trusts the CALLER (the API-key
 * holder, i.e. the agent integrating Carapace) to label the provenance of each
 * piece of content honestly. It protects that agent from untrusted CONTENT, not
 * from a compromised caller. So provenance.channel and provenance.authenticated
 * are passed through as the caller reports them, defaulting authenticated to
 * false. The usual injection vectors (web, tool, subagent, ambient) are gated
 * regardless of what the caller claims, because those channels carry low trust
 * ceilings by config. A caller that holds the API key already controls its own
 * agent's memory; lying to its own firewall only harms itself.
 */
import { createCarapace, DEFAULT_CONFIG, scanInjection } from "../../src/index.js";
import type { CarapaceConfig, ChannelKind, DetectorResult, Provenance, TrustTier } from "../../src/index.js";
import { sha256 } from "../../src/hash.js";
import { LedgerDO, type LedgerRecord, type RateLimitDecision } from "./ledger-do.js";
import { modelOptionsFromEnv, precomputedDetector, runModelGuard, type ModelScan } from "./model-detector.js";

export { LedgerDO };

interface Env {
  LEDGER: DurableObjectNamespace;
  /** Workers AI binding. Optional so the Worker still runs (heuristic-only) without it. */
  AI?: Ai;
  /** Comma-separated list of accepted API keys. */
  CARAPACE_API_KEYS?: string;
  /** Optional PEM Ed25519 public key for capability verification. */
  CARAPACE_AUTHORITY_PUBKEY?: string;
  /** Workers AI model id for the guard detector. Defaults to the verified guard model. */
  CARAPACE_MODEL_ID?: string;
  /** Set to "false" to disable the model detector even when the AI binding is present. */
  CARAPACE_MODEL_ENABLED?: string;
  /** Max accepted requests per tenant per window. Default 120. */
  CARAPACE_RATE_LIMIT?: string;
  /** Rate-limit window in milliseconds. Default 60000. */
  CARAPACE_RATE_WINDOW_MS?: string;
}

const VERSION = "0.1.0";
const VALID_CHANNELS: ReadonlySet<string> = new Set<ChannelKind>([
  "direct", "group", "ambient", "web", "api", "tool", "subagent", "filesystem",
]);
const VALID_TRUST: ReadonlySet<string> = new Set<TrustTier>(["T0", "T1", "T2", "T3", "T4"]);

/** Hard ceiling on a single content field, to bound model cost and memory. */
const MAX_CONTENT_CHARS = 50_000;
/** Hard ceiling on the raw request body, rejected before parsing. */
const MAX_BODY_BYTES = 256 * 1024;
const DEFAULT_RATE_LIMIT = 120;
const DEFAULT_RATE_WINDOW_MS = 60_000;

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const bad = (message: string, status = 400): Response => json({ error: message }, status);

/** Lazily build a config once per isolate. The authority key is read from env or generated ephemerally. */
let cachedPubkey: string | undefined;
const buildConfig = async (env: Env): Promise<CarapaceConfig> => {
  if (env.CARAPACE_AUTHORITY_PUBKEY !== undefined && env.CARAPACE_AUTHORITY_PUBKEY.length > 0) {
    return { ...DEFAULT_CONFIG, authorityPublicKeyPem: env.CARAPACE_AUTHORITY_PUBKEY };
  }
  if (cachedPubkey === undefined) {
    const { generateKeyPairSync } = await import("node:crypto");
    const { publicKey } = generateKeyPairSync("ed25519");
    cachedPubkey = publicKey.export({ type: "spki", format: "pem" }).toString();
  }
  return { ...DEFAULT_CONFIG, authorityPublicKeyPem: cachedPubkey };
};

const authTenant = (request: Request, env: Env): string | undefined => {
  const header = request.headers.get("authorization") ?? "";
  const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  if (token.length === 0) return undefined;
  const accepted = (env.CARAPACE_API_KEYS ?? "").split(",").map((k) => k.trim()).filter((k) => k.length > 0);
  return accepted.includes(token) ? token : undefined;
};

type Validated<T> = { ok: true; value: T } | { ok: false; error: string };

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Validate a client-supplied provenance. Strict on types: a present field with
 * the wrong type is rejected rather than silently coerced. Missing optional
 * fields fall back to untrusted defaults (authenticated defaults to false).
 */
const validateProvenance = (raw: unknown): Validated<Provenance> => {
  if (raw !== undefined && !isPlainObject(raw)) return { ok: false, error: "provenance must be an object" };
  const p: Record<string, unknown> = isPlainObject(raw) ? raw : {};

  const channel = p.channel === undefined ? "api" : p.channel;
  if (typeof channel !== "string" || !VALID_CHANNELS.has(channel)) {
    return { ok: false, error: "provenance.channel is invalid" };
  }
  if (p.source !== undefined && typeof p.source !== "string") return { ok: false, error: "provenance.source must be a string" };
  if (p.actor !== undefined && typeof p.actor !== "string") return { ok: false, error: "provenance.actor must be a string" };
  if (p.authenticated !== undefined && typeof p.authenticated !== "boolean") return { ok: false, error: "provenance.authenticated must be a boolean" };
  if (p.capturedAt !== undefined && typeof p.capturedAt !== "string") return { ok: false, error: "provenance.capturedAt must be a string" };

  return {
    ok: true,
    value: {
      source: typeof p.source === "string" ? p.source : `${channel}:carapace-service`,
      channel: channel as ChannelKind,
      authenticated: p.authenticated === true,
      capturedAt: typeof p.capturedAt === "string" ? p.capturedAt : new Date().toISOString(),
      ...(typeof p.actor === "string" ? { actor: p.actor } : {}),
    },
  };
};

/** Validate the optional corroboration array: each entry must be {hash, trust}. */
const validateCorroboration = (raw: unknown): Validated<{ hash: string; trust: TrustTier }[] | undefined> => {
  if (raw === undefined) return { ok: true, value: undefined };
  if (!Array.isArray(raw)) return { ok: false, error: "corroboration must be an array" };
  const out: { hash: string; trust: TrustTier }[] = [];
  for (const item of raw) {
    if (!isPlainObject(item) || typeof item.hash !== "string" || typeof item.trust !== "string" || !VALID_TRUST.has(item.trust)) {
      return { ok: false, error: "corroboration entries must be { hash: string, trust: T0..T4 }" };
    }
    out.push({ hash: item.hash, trust: item.trust as TrustTier });
  }
  return { ok: true, value: out };
};

/** Reject oversized bodies before parsing, and parse JSON with a friendly 400 on failure. */
const readJsonBody = async (request: Request): Promise<Validated<Record<string, unknown>>> => {
  const declared = request.headers.get("content-length");
  if (declared !== undefined && declared !== null && Number(declared) > MAX_BODY_BYTES) {
    return { ok: false, error: "request body too large" };
  }
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return { ok: false, error: "request body too large" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "body must be JSON" };
  }
  if (!isPlainObject(parsed)) return { ok: false, error: "body must be a JSON object" };
  return { ok: true, value: parsed };
};

const appendToLedger = async (env: Env, tenant: string, record: LedgerRecord): Promise<{ head: string; index: number; count: number }> => {
  const stub = env.LEDGER.get(env.LEDGER.idFromName(tenant));
  const res = await stub.fetch("https://ledger/append", {
    method: "POST",
    body: JSON.stringify(record),
    headers: { "content-type": "application/json" },
  });
  return (await res.json()) as { head: string; index: number; count: number };
};

const ledgerQuery = async (env: Env, tenant: string, path: "head" | "verify"): Promise<Response> => {
  const stub = env.LEDGER.get(env.LEDGER.idFromName(tenant));
  const res = await stub.fetch(`https://ledger/${path}`);
  return json(await res.json());
};

const parsePositiveInt = (raw: string | undefined, fallback: number): number => {
  const n = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

/**
 * Per-tenant rate limit, enforced by the tenant's own Durable Object (the
 * natural per-tenant anchor). Fails open if the DO is unreachable so a ledger
 * blip cannot take the firewall offline.
 */
const checkRateLimit = async (env: Env, tenant: string): Promise<RateLimitDecision> => {
  const limit = parsePositiveInt(env.CARAPACE_RATE_LIMIT, DEFAULT_RATE_LIMIT);
  const windowMs = parsePositiveInt(env.CARAPACE_RATE_WINDOW_MS, DEFAULT_RATE_WINDOW_MS);
  try {
    const stub = env.LEDGER.get(env.LEDGER.idFromName(tenant));
    const res = await stub.fetch("https://ledger/limit", {
      method: "POST",
      body: JSON.stringify({ limit, windowMs }),
      headers: { "content-type": "application/json" },
    });
    return (await res.json()) as RateLimitDecision;
  } catch {
    return { allowed: true, remaining: limit, resetMs: windowMs };
  }
};

const modelEnabled = (env: Env): boolean =>
  env.AI !== undefined && (env.CARAPACE_MODEL_ENABLED ?? "true").toLowerCase() !== "false";

/** Run the model guard if enabled; otherwise return a benign, unused scan. */
const scanWithModel = async (env: Env, content: string): Promise<ModelScan> => {
  const options = modelOptionsFromEnv(env.CARAPACE_MODEL_ID);
  if (!modelEnabled(env)) {
    return { used: false, modelId: options.modelId, result: { flagged: false, score: 0, detector: "workers-ai-guard", reasons: [] } };
  }
  return runModelGuard(env.AI, content, options);
};

const detectorView = (r: DetectorResult): { flagged: boolean; score: number; reasons: readonly string[] } => ({
  flagged: r.flagged,
  score: r.score,
  reasons: r.reasons,
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "carapace", version: VERSION, ts: new Date().toISOString() });
    }

    const tenant = authTenant(request, env);
    if (tenant === undefined) return bad("missing or invalid API key (Authorization: Bearer <key>)", 401);

    const rate = await checkRateLimit(env, tenant);
    if (!rate.allowed) {
      const retryAfter = Math.ceil(rate.resetMs / 1000);
      return new Response(JSON.stringify({ error: "rate limit exceeded", retryAfterMs: rate.resetMs }), {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": String(retryAfter) },
      });
    }

    if (request.method === "GET" && url.pathname === "/v1/ledger/head") return ledgerQuery(env, tenant, "head");
    if (request.method === "GET" && url.pathname === "/v1/ledger/verify") return ledgerQuery(env, tenant, "verify");

    if (request.method === "POST" && (url.pathname === "/v1/ingress" || url.pathname === "/v1/promote")) {
      const parsed = await readJsonBody(request);
      if (!parsed.ok) return bad(parsed.error, parsed.error === "request body too large" ? 413 : 400);
      const body = parsed.value;

      if (typeof body.content !== "string" || body.content.length === 0) return bad("content (non-empty string) is required");
      if (body.content.length > MAX_CONTENT_CHARS) return bad(`content exceeds ${MAX_CONTENT_CHARS} characters`, 413);
      const prov = validateProvenance(body.provenance);
      if (!prov.ok) return bad(prov.error);
      const provenance = prov.value;

      // Run the async model guard first, then inject its verdict as a precomputed
      // sync Detector. The heuristic is computed standalone too, so the response
      // can report each arm separately (heuristic-only vs heuristic+model).
      const modelScan = await scanWithModel(env, body.content);
      const heuristic = scanInjection(body.content, provenance);
      const cp = createCarapace(await buildConfig(env), modelScan.used ? { detectors: [precomputedDetector(modelScan.result)] } : {});
      const envelope = cp.onIngress({ content: body.content, provenance });

      const signals = {
        heuristic: detectorView(heuristic),
        model: {
          used: modelScan.used,
          modelId: modelScan.modelId,
          ...detectorView(modelScan.result),
          ...(modelScan.error !== undefined ? { error: modelScan.error } : {}),
        },
      };

      if (url.pathname === "/v1/ingress") {
        const ledger = await appendToLedger(env, tenant, {
          op: "ingress",
          contentHash: envelope.hash,
          verdict: envelope.quarantined ? "quarantined" : "ingested",
          reasons: envelope.scan.injection.reasons,
          trust: envelope.trust,
          ts: new Date().toISOString(),
        });
        return json({
          hash: envelope.hash,
          trust: envelope.trust,
          quarantined: envelope.quarantined,
          injection: { flagged: envelope.scan.injection.flagged, score: envelope.scan.injection.score, reasons: envelope.scan.injection.reasons, detector: envelope.scan.injection.detector },
          exfil: { flagged: envelope.scan.exfil.flagged, score: envelope.scan.exfil.score, reasons: envelope.scan.exfil.reasons },
          signals,
          ledger,
        });
      }

      // /v1/promote
      const target = body.target === "chroma" || body.target === "obsidian" ? body.target : "MEMORY.md";
      const corr = validateCorroboration(body.corroboration);
      if (!corr.ok) return bad(corr.error);
      if (body.touchesIdentity !== undefined && typeof body.touchesIdentity !== "boolean") return bad("touchesIdentity must be a boolean");
      const corroboration = corr.value;
      const touchesIdentity = body.touchesIdentity === true;
      const decision = cp.onMemoryWrite({
        envelope,
        target,
        ...(corroboration ? { corroboration } : {}),
        ...(touchesIdentity ? { touchesIdentity } : {}),
      });
      const ledger = await appendToLedger(env, tenant, {
        op: "promote",
        contentHash: envelope.hash,
        verdict: decision.verdict,
        reasons: decision.reasons,
        trust: envelope.trust,
        ts: new Date().toISOString(),
      });
      return json({
        verdict: decision.verdict,
        reasons: decision.reasons,
        hash: envelope.hash,
        trust: envelope.trust,
        quarantined: envelope.quarantined,
        signals,
        ledger,
      });
    }

    return bad("not found", 404);
  },
};

// Touch sha256 so the shared hash module is part of the bundle graph (used by the DO).
void sha256;
