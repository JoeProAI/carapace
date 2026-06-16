import type { DetectorResult, PiiKind } from "../types.js";

/**
 * Heuristic exfiltration / secret detector.
 *
 * Used on egress (does this outbound payload carry secrets?) and on ingress
 * (is someone trying to get the agent to repeat back sensitive material?).
 * The secret-file registry is passed in so deployment-specific filenames
 * (arweave wallets, firebase service accounts) are caught by name.
 */

interface Signal {
  re: RegExp;
  kind: PiiKind;
  weight: number;
  reason: string;
}

const SIGNALS: Signal[] = [
  { re: /\bsk[-_][A-Za-z0-9][A-Za-z0-9_-]{10,}/i, kind: "api-key", weight: 0.9, reason: "openai-stripe-style-key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, kind: "api-key", weight: 0.9, reason: "aws-access-key-id" },
  { re: /\bghp_[A-Za-z0-9]{30,}\b/, kind: "api-key", weight: 0.9, reason: "github-pat" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, kind: "api-key", weight: 0.85, reason: "slack-token" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, kind: "credential", weight: 1, reason: "private-key-block" },
  { re: /"private_key"\s*:/, kind: "credential", weight: 0.8, reason: "service-account-json" },
  { re: /\b[A-Za-z0-9_-]{43}\b/, kind: "wallet", weight: 0.2, reason: "possible-arweave-address" },
  { re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, kind: "email", weight: 0.15, reason: "email-address" },
];

export const scanExfil = (content: string, secretFileRegistry: readonly string[] = []): DetectorResult => {
  const reasons: string[] = [];
  let score = 0;

  for (const sig of SIGNALS) {
    if (sig.re.test(content)) {
      score += sig.weight;
      reasons.push(sig.reason);
    }
  }

  for (const file of secretFileRegistry) {
    if (content.includes(file)) {
      score += 0.6;
      reasons.push(`references-secret-file:${file}`);
    }
  }

  const clamped = Math.min(score, 1);
  return {
    flagged: clamped >= 0.5,
    score: Number(clamped.toFixed(3)),
    detector: "heuristic-exfil",
    reasons: [...new Set(reasons)],
  };
};
