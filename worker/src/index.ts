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
import { createCarapace, DEFAULT_CONFIG } from "../../src/index.js";
import type { CarapaceConfig, ChannelKind, Provenance, TrustTier } from "../../src/index.js";
import { sha256 } from "../../src/hash.js";
import { LedgerDO, type LedgerRecord } from "./ledger-do.js";

export { LedgerDO };

interface Env {
  LEDGER: DurableObjectNamespace;
  /** Comma-separated list of accepted API keys. */
  CARAPACE_API_KEYS?: string;
  /** Optional PEM Ed25519 public key for capability verification. */
  CARAPACE_AUTHORITY_PUBKEY?: string;
}

const VERSION = "0.1.0";
const VALID_CHANNELS: ReadonlySet<string> = new Set<ChannelKind>([
  "direct", "group", "ambient", "web", "api", "tool", "subagent", "filesystem",
]);

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

/** Normalize a client-supplied provenance. authenticated defaults to false (untrusted). */
const normalizeProvenance = (raw: unknown): Provenance | undefined => {
  const p = (raw ?? {}) as Record<string, unknown>;
  const channel = typeof p.channel === "string" ? p.channel : "api";
  if (!VALID_CHANNELS.has(channel)) return undefined;
  return {
    source: typeof p.source === "string" ? p.source : `${channel}:carapace-service`,
    channel: channel as ChannelKind,
    authenticated: p.authenticated === true,
    capturedAt: typeof p.capturedAt === "string" ? p.capturedAt : new Date().toISOString(),
    ...(typeof p.actor === "string" ? { actor: p.actor } : {}),
  };
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "carapace", version: VERSION, ts: new Date().toISOString() });
    }

    const tenant = authTenant(request, env);
    if (tenant === undefined) return bad("missing or invalid API key (Authorization: Bearer <key>)", 401);

    if (request.method === "GET" && url.pathname === "/v1/ledger/head") return ledgerQuery(env, tenant, "head");
    if (request.method === "GET" && url.pathname === "/v1/ledger/verify") return ledgerQuery(env, tenant, "verify");

    if (request.method === "POST" && (url.pathname === "/v1/ingress" || url.pathname === "/v1/promote")) {
      let body: Record<string, unknown>;
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {
        return bad("body must be JSON");
      }
      if (typeof body.content !== "string" || body.content.length === 0) return bad("content (non-empty string) is required");
      const provenance = normalizeProvenance(body.provenance);
      if (provenance === undefined) return bad("provenance.channel is invalid");

      const cp = createCarapace(await buildConfig(env));
      const envelope = cp.onIngress({ content: body.content, provenance });

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
          injection: { flagged: envelope.scan.injection.flagged, score: envelope.scan.injection.score, reasons: envelope.scan.injection.reasons },
          exfil: { flagged: envelope.scan.exfil.flagged, score: envelope.scan.exfil.score, reasons: envelope.scan.exfil.reasons },
          ledger,
        });
      }

      // /v1/promote
      const target = body.target === "chroma" || body.target === "obsidian" ? body.target : "MEMORY.md";
      const corroboration = Array.isArray(body.corroboration)
        ? (body.corroboration as { hash: string; trust: TrustTier }[])
        : undefined;
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
        ledger,
      });
    }

    return bad("not found", 404);
  },
};

// Touch sha256 so the shared hash module is part of the bundle graph (used by the DO).
void sha256;
