/**
 * Input normalization to defeat trivial detector bypasses.
 *
 * Attackers obfuscate: zero-width characters, homoglyphs, spaced-out words,
 * case tricks, base64/hex payloads. We canonicalize before pattern-matching so
 * "ig<zwsp>nore" and "i g n o r e" and the Cyrillic lookalike all collapse to
 * the same thing. This is defense-in-depth layered on top of the provenance
 * gate, never a replacement for it.
 */

const ZERO_WIDTH = /[​-‏‪-‮⁠﻿­]/g;

// Common Cyrillic and Greek confusables mapped to their Latin lookalikes.
const HOMOGLYPHS: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
  "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "к": "k",
  "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i",
  "κ": "k", "ν": "v", "υ": "u",
  "Ι": "i", "Ο": "o", "Ρ": "p",
};

const foldHomoglyphs = (s: string): string =>
  s.replace(/[^ -~]/g, (ch) => HOMOGLYPHS[ch] ?? ch);

const looksTextual = (s: string): boolean => /[ -~]{4,}/.test(s) && !s.includes("�");

/** Decode base64 and hex blobs so encoded payloads can be scanned as plain text. */
const tryDecode = (raw: string): string => {
  const found: string[] = [];
  for (const blob of raw.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? []) {
    try {
      const d = Buffer.from(blob, "base64").toString("utf8");
      if (looksTextual(d)) found.push(d);
    } catch {
      /* not base64, ignore */
    }
  }
  for (const blob of raw.match(/(?:[0-9a-fA-F]{2}){8,}/g) ?? []) {
    try {
      const d = Buffer.from(blob, "hex").toString("utf8");
      if (looksTextual(d)) found.push(d);
    } catch {
      /* not hex, ignore */
    }
  }
  return found.join(" ");
};

export interface NormalizedText {
  /** NFKC, zero-width stripped, homoglyph-folded, lowercased, whitespace-collapsed. */
  normalized: string;
  /** normalized with every non-alphanumeric removed, to catch spaced/punctuated splits. */
  compact: string;
  /** any base64/hex segments decoded to text, lowercased. */
  decoded: string;
}

export const normalizeForDetection = (raw: string): NormalizedText => {
  const stripped = foldHomoglyphs(raw.normalize("NFKC").replace(ZERO_WIDTH, ""));
  const normalized = stripped.toLowerCase().replace(/\s+/g, " ").trim();
  const compact = normalized.replace(/[^a-z0-9]+/g, "");
  const decoded = tryDecode(raw).toLowerCase();
  return { normalized, compact, decoded };
};
