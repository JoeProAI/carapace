import type { CarapaceConfig, RecallItem } from "./types.js";
import { trustRank } from "./types.js";
import { atLeast } from "./provenance.js";
import { scanInjection } from "./detectors/injection.js";

const DAY_MS = 86_400_000;

/**
 * Recency multiplier in [0,1] via exponential decay. A memory loses half its
 * recall weight every halfLifeDays. This is the temporal-decay half of the
 * memory-sanitization defense in arXiv:2601.05504: a one-shot injected memory
 * that is never re-corroborated fades, while genuinely recurring facts stay hot.
 */
export const recencyWeight = (capturedAt: string, now: number, halfLifeDays: number): number => {
  const ts = Date.parse(capturedAt);
  if (Number.isNaN(ts) || halfLifeDays <= 0) return 0;
  const ageDays = Math.max(0, (now - ts) / DAY_MS);
  return Math.pow(0.5, ageDays / halfLifeDays);
};

/** Combined recall score: trust rank scaled by recency. Quarantined items score 0. */
export const recallScore = (item: RecallItem, now: number, halfLifeDays: number): number => {
  if (item.quarantined) return 0;
  const base = (trustRank(item.trust) + 1) / 5; // 0.2 .. 1.0
  return base * recencyWeight(item.capturedAt, now, halfLifeDays);
};

export interface FilterResult {
  kept: RecallItem[];
  dropped: { item: RecallItem; reason: string }[];
}

/**
 * Trust-aware retrieval. Drops quarantined items, items below the recall trust
 * floor, and items whose stored content trips injection patterns (pattern-based
 * filtering, the other half of the arXiv:2601.05504 defense). Survivors are
 * ranked by combined trust-and-recency score.
 */
export const filterRecall = (
  items: readonly RecallItem[],
  config: CarapaceConfig,
  now: number = Date.now(),
): FilterResult => {
  const kept: RecallItem[] = [];
  const dropped: { item: RecallItem; reason: string }[] = [];

  for (const item of items) {
    if (item.quarantined) {
      dropped.push({ item, reason: "quarantined" });
      continue;
    }
    if (!atLeast(item.trust, config.recall.minTrust)) {
      dropped.push({ item, reason: `below-recall-min-trust:${item.trust}` });
      continue;
    }
    if (scanInjection(item.content).flagged) {
      dropped.push({ item, reason: "injection-pattern-in-stored-memory" });
      continue;
    }
    kept.push(item);
  }

  kept.sort(
    (a, b) => recallScore(b, now, config.recall.halfLifeDays) - recallScore(a, now, config.recall.halfLifeDays),
  );
  return { kept, dropped };
};
