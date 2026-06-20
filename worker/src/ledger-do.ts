/**
 * LedgerDO: a per-tenant, append-only, hash-chained audit ledger backed by
 * Durable Object storage.
 *
 * Why a Durable Object: the ledger needs ordered, strongly-consistent,
 * append-only writes. A Durable Object is single-threaded and strongly
 * consistent, so one DO per tenant serializes writes with no races and gives a
 * tamper-evident chain. (KV is eventually consistent and cannot do this.)
 *
 * The chain uses the same scheme as the in-process ledger: each record's hash
 * is sha256(prevHash + canonicalJSON(record)), seeded from GENESIS.
 */
import { sha256, GENESIS } from "../../src/hash.js";

/** The application-level fields of a ledger record. Order matters for the hash. */
export interface LedgerRecord {
  op: "ingress" | "promote" | "recall";
  contentHash: string;
  verdict: string;
  reasons: string[];
  trust: string;
  ts: string;
}

interface StoredEntry extends LedgerRecord {
  index: number;
  prevHash: string;
  recordHash: string;
}

/** Stable stringify: object keys are emitted in a fixed order so the hash is deterministic. */
const canonical = (r: LedgerRecord): string =>
  JSON.stringify([r.op, r.contentHash, r.verdict, r.reasons, r.trust, r.ts]);

const key = (index: number): string => `e:${index.toString().padStart(12, "0")}`;

/** Fixed-window rate-limit decision returned to the Worker. */
export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  /** Milliseconds until the current window resets. */
  resetMs: number;
}

interface RateLimitRequest {
  limit: number;
  windowMs: number;
}

export class LedgerDO implements DurableObject {
  /**
   * Per-tenant rate-limit window, held in memory. One LedgerDO instance exists
   * per tenant and is single-threaded, so this counter is naturally per-tenant
   * and race-free. It resets if the instance is evicted, which fails open; that
   * is acceptable for a basic abuse limiter sitting in front of the firewall.
   */
  private window: { startedAt: number; count: number } | undefined;

  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/append") {
      const record = (await request.json()) as LedgerRecord;
      return Response.json(await this.append(record));
    }
    if (request.method === "POST" && url.pathname === "/limit") {
      const { limit, windowMs } = (await request.json()) as RateLimitRequest;
      return Response.json(this.rateLimit(limit, windowMs));
    }
    if (url.pathname === "/head") {
      const head = (await this.state.storage.get<string>("head")) ?? GENESIS;
      const count = (await this.state.storage.get<number>("count")) ?? 0;
      return Response.json({ head, count });
    }
    if (url.pathname === "/verify") {
      return Response.json(await this.verify());
    }
    return new Response("not found", { status: 404 });
  }

  /** Fixed-window counter. Increments on each call and reports the decision. */
  private rateLimit(limit: number, windowMs: number): RateLimitDecision {
    const now = Date.now();
    if (this.window === undefined || now - this.window.startedAt >= windowMs) {
      this.window = { startedAt: now, count: 0 };
    }
    this.window.count += 1;
    const remaining = Math.max(0, limit - this.window.count);
    const resetMs = Math.max(0, this.window.startedAt + windowMs - now);
    return { allowed: this.window.count <= limit, remaining, resetMs };
  }

  private async append(record: LedgerRecord): Promise<{ head: string; index: number; count: number }> {
    // Serialize against concurrent appends so the chain has no gaps or races.
    return this.state.blockConcurrencyWhile(async () => {
      const prevHash = (await this.state.storage.get<string>("head")) ?? GENESIS;
      const count = (await this.state.storage.get<number>("count")) ?? 0;
      const recordHash = sha256(prevHash + canonical(record));
      const entry: StoredEntry = { ...record, index: count, prevHash, recordHash };
      await this.state.storage.put({ [key(count)]: entry, head: recordHash, count: count + 1 });
      return { head: recordHash, index: count, count: count + 1 };
    });
  }

  /**
   * Recompute the chain from stored entries; report the first break if any.
   *
   * The whole read sweep runs inside blockConcurrencyWhile so it observes a
   * single consistent snapshot. Without it, an append could interleave between
   * the count/head reads and the per-entry reads, making verify() compare
   * entries against a head that has already moved and report a false break (or
   * miss a real one). Verification must not race writes.
   */
  private async verify(): Promise<{ valid: boolean; count: number; brokenAt?: number }> {
    return this.state.blockConcurrencyWhile(async () => {
      const count = (await this.state.storage.get<number>("count")) ?? 0;
      const head = (await this.state.storage.get<string>("head")) ?? GENESIS;
      let prev = GENESIS;
      for (let i = 0; i < count; i += 1) {
        const entry = await this.state.storage.get<StoredEntry>(key(i));
        if (entry === undefined) return { valid: false, count, brokenAt: i };
        const expect = sha256(prev + canonical(entry));
        if (entry.prevHash !== prev || entry.recordHash !== expect) {
          return { valid: false, count, brokenAt: i };
        }
        prev = entry.recordHash;
      }
      return { valid: prev === head, count };
    });
  }
}
