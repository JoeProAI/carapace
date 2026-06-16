import type { Decision, LedgerEntry, LedgerEventKind } from "./types.js";
import { GENESIS, sha256 } from "./hash.js";

type LedgerMeta = Record<string, string | number | boolean>;

interface SerializableFields {
  seq: number;
  at: string;
  kind: LedgerEventKind;
  subjectHash: string;
  verdict: LedgerEntry["verdict"];
  reasons: string[];
  meta: LedgerMeta;
  prevHash: string;
}

/**
 * Append-only, hash-chained audit log.
 *
 * Each entry commits to the previous via prevHash, so any edit to history
 * breaks the chain and is detectable with verify(). This is the forensic spine:
 * when something gets into memory it should not have, the ledger says what,
 * from where, and why it was allowed.
 */
export class Ledger {
  private readonly entries: LedgerEntry[] = [];
  private readonly persist: ((entry: LedgerEntry) => void) | undefined;

  constructor(persist?: (entry: LedgerEntry) => void) {
    this.persist = persist;
  }

  private static serialize(fields: SerializableFields): string {
    // Fixed key order so append and verify always hash identical bytes.
    return JSON.stringify([
      fields.seq,
      fields.at,
      fields.kind,
      fields.subjectHash,
      fields.verdict,
      fields.reasons,
      fields.meta,
      fields.prevHash,
    ]);
  }

  append(kind: LedgerEventKind, subjectHash: string, decision: Decision, meta?: LedgerMeta): LedgerEntry {
    const prevHash = this.entries.at(-1)?.entryHash ?? GENESIS;
    const fields: SerializableFields = {
      seq: this.entries.length,
      at: new Date().toISOString(),
      kind,
      subjectHash,
      verdict: decision.verdict,
      reasons: decision.reasons,
      meta: meta ?? {},
      prevHash,
    };
    const entryHash = sha256(Ledger.serialize(fields));
    const entry: LedgerEntry = {
      ...fields,
      entryHash,
      ...(meta ? { meta } : {}),
    };
    this.entries.push(entry);
    this.persist?.(entry);
    return entry;
  }

  /** Walk the chain and confirm no entry was altered or reordered. */
  verify(): { valid: boolean; brokeAt?: number } {
    let prev = GENESIS;
    for (const e of this.entries) {
      if (e.prevHash !== prev) return { valid: false, brokeAt: e.seq };
      const recomputed = sha256(
        Ledger.serialize({
          seq: e.seq,
          at: e.at,
          kind: e.kind,
          subjectHash: e.subjectHash,
          verdict: e.verdict,
          reasons: e.reasons,
          meta: e.meta ?? {},
          prevHash: e.prevHash,
        }),
      );
      if (recomputed !== e.entryHash) return { valid: false, brokeAt: e.seq };
      prev = e.entryHash;
    }
    return { valid: true };
  }

  all(): readonly LedgerEntry[] {
    return this.entries;
  }

  head(): string {
    return this.entries.at(-1)?.entryHash ?? GENESIS;
  }
}
