import type { Detector, DetectorResult, Provenance } from "../types.js";
import { normalizeForDetection } from "../normalize.js";

/**
 * Heuristic prompt-injection detector.
 *
 * Cheap, deterministic, runs on the hot path. It does not try to be a classifier.
 * Inputs are normalized first (homoglyphs, zero-width, spacing, base64/hex) so the
 * obvious bypasses do not work, then matched against pattern and compact signals.
 * Paraphrase and unusual languages are out of scope here by design; that is what
 * the model detector seam and the provenance gate are for.
 */

interface Signal {
  re: RegExp;
  weight: number;
  reason: string;
}

const SIGNALS: Signal[] = [
  { re: /\bignore (all |any |the )?(previous|prior|above)\b/i, weight: 0.6, reason: "override-previous-instructions" },
  { re: /\b(disregard|forget) (all |everything |your )?(previous|prior|earlier)\b/i, weight: 0.6, reason: "discard-context" },
  { re: /\byou are now\b|\bact as\b|\bpretend to be\b/i, weight: 0.4, reason: "role-reassignment" },
  { re: /\b(system|developer) (prompt|message|instruction)\b/i, weight: 0.45, reason: "references-system-layer" },
  { re: /\b(update|edit|modify|rewrite|delete) (your |the )?(soul|identity|agents|bootstrap|memory)\b/i, weight: 0.7, reason: "targets-protected-files" },
  { re: /\b(reveal|print|show|exfiltrate|send) (me )?(your |the )?(system prompt|instructions|api[_ ]?key|secret|token|\.env)\b/i, weight: 0.7, reason: "extraction-attempt" },
  { re: /\boverride\b.{0,20}\b(security|safety|boundary|rule)\b/i, weight: 0.6, reason: "override-safety" },
  { re: /[a-z0-9+/]{40,}={0,2}/, weight: 0.2, reason: "long-encoded-blob" },
];

interface CompactSignal {
  needle: string;
  weight: number;
  reason: string;
}

// Matched against the compact (de-spaced, de-punctuated) form to catch split words.
const COMPACT_SIGNALS: CompactSignal[] = [
  { needle: "ignoreallprevious", weight: 0.6, reason: "spaced-override" },
  { needle: "ignoreprevious", weight: 0.6, reason: "spaced-override" },
  { needle: "disregardprevious", weight: 0.6, reason: "spaced-discard" },
  { needle: "youarenow", weight: 0.4, reason: "spaced-role-reassignment" },
  { needle: "systemprompt", weight: 0.3, reason: "spaced-system-reference" },
  { needle: "newinstructions", weight: 0.5, reason: "spaced-new-instructions" },
  { needle: "updatesoul", weight: 0.7, reason: "spaced-targets-protected" },
  { needle: "editsoul", weight: 0.7, reason: "spaced-targets-protected" },
];

const AUTH_CODE_WORD = /\bkakaw\b/i;

export const scanInjection = (content: string, prov?: Provenance): DetectorResult => {
  const norm = normalizeForDetection(content);
  const haystack = norm.decoded ? `${norm.normalized}\n${norm.decoded}` : norm.normalized;
  const reasons: string[] = [];
  let score = 0;

  for (const sig of SIGNALS) {
    if (sig.re.test(haystack)) {
      score += sig.weight;
      reasons.push(sig.reason);
    }
  }
  for (const cs of COMPACT_SIGNALS) {
    if (norm.compact.includes(cs.needle)) {
      score += cs.weight;
      reasons.push(cs.reason);
    }
  }

  if (AUTH_CODE_WORD.test(haystack) || norm.compact.includes("kakaw")) {
    const fromPrincipal = prov?.channel === "direct" && prov.authenticated === true;
    if (!fromPrincipal) {
      score += 0.9;
      reasons.push("authorization-code-word-from-untrusted-channel");
    }
  }

  const clamped = Math.min(score, 1);
  return {
    flagged: clamped >= 0.5,
    score: Number(clamped.toFixed(3)),
    detector: "heuristic-injection",
    reasons: [...new Set(reasons)],
  };
};

/** The built-in heuristic detector, exposed as a pluggable Detector. */
export const heuristicInjectionDetector: Detector = {
  name: "heuristic-injection",
  scan: (content, provenance) => scanInjection(content, provenance),
};

/**
 * Merge orthogonal detector results into one composite signal: max score,
 * unioned reasons, flagged if any detector flags or the combined score crosses
 * the line. This is the seam where a model detector joins the heuristics.
 */
export const combineInjectionResults = (results: readonly DetectorResult[]): DetectorResult => {
  const first = results[0];
  if (results.length === 1 && first) return first;
  const score = results.reduce((max, r) => Math.max(max, r.score), 0);
  const reasons = [...new Set(results.flatMap((r) => r.reasons))];
  return {
    flagged: results.some((r) => r.flagged) || score >= 0.5,
    score: Number(score.toFixed(3)),
    detector: "composite",
    reasons,
  };
};
