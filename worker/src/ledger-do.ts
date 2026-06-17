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

export class LedgerDO implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/append") {
      const record = (await request.json()) as LedgerRecord;
      return Response.json(await this.append(record));
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

  /** Recompute the chain from stored entries; report the first break if any. */
  private async verify(): Promise<{ valid: boolean; count: number; brokenAt?: number }> {
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
  }
}
