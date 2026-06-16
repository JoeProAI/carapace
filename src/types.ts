/**
 * Carapace core types.
 *
 * Trust is a property of provenance, not of repetition. Everything in here
 * exists to keep that invariant true from ingress to durable memory.
 */

/**
 * Trust tiers, highest to lowest.
 * T0  Joe, direct, on an authenticated channel. Can authorize protected writes.
 * T1  First-party deterministic sources the agent owns (its own verified memory, local FS it controls).
 * T2  Known/reputable web and named APIs. Promotable only with corroboration.
 * T3  Untrusted web, ambient capture, shared-channel messages. Context only, never auto-promoted.
 * T4  Sub-agents and unverified tool output. Treated as T3 or lower until verified.
 */
export type TrustTier = "T0" | "T1" | "T2" | "T3" | "T4";

export const TRUST_ORDER: readonly TrustTier[] = ["T4", "T3", "T2", "T1", "T0"];

/** Numeric rank for comparisons. Higher is more trusted. */
export const trustRank = (tier: TrustTier): number => TRUST_ORDER.indexOf(tier);

export type ChannelKind =
  | "direct" // 1:1 with the principal on an authenticated surface
  | "group" // shared channel, multiple humans
  | "ambient" // wearable / always-on capture
  | "web" // fetched or scraped content
  | "api" // named third-party API
  | "tool" // first-party tool result
  | "subagent" // spawned worker
  | "filesystem"; // local files the agent reads

export interface Provenance {
  /** Stable identifier of the upstream source, e.g. "limitless", "crawl4ai:example.com", "discord:guild/123". */
  source: string;
  channel: ChannelKind;
  /** Who produced the content, when known. "joe", "unknown", a user id, etc. */
  actor?: string;
  /** Whether the channel itself is cryptographically/operationally authenticated as the principal. */
  authenticated?: boolean;
  capturedAt: string; // ISO 8601
}

export type DetectorName = "heuristic-injection" | "heuristic-exfil" | "promptguard2" | "gemma3-classifier" | "composite";

export interface DetectorResult {
  flagged: boolean;
  /** 0..1 confidence that the content is hostile/sensitive. */
  score: number;
  detector: DetectorName;
  /** Human-readable reasons. Short. */
  reasons: string[];
}

/**
 * A pluggable signal source. The built-in heuristic detector runs on the sync
 * hot path. Additional orthogonal detectors can be supplied and merged into a
 * composite signal, which is the composite-trust-scoring defense described in
 * arXiv:2601.05504. A model detector such as PromptGuard 2 is the next one to
 * add behind this same interface; it is documented, not faked.
 */
export interface Detector {
  readonly name: DetectorName;
  scan(content: string, provenance: Provenance): DetectorResult;
}

export type PiiKind = "secret" | "api-key" | "wallet" | "email" | "phone" | "credential";

export interface Envelope {
  content: string;
  provenance: Provenance;
  trust: TrustTier;
  scan: {
    injection: DetectorResult;
    exfil: DetectorResult;
  };
  /** sha256 of content, hex. Stable id for ledger + dedup. */
  hash: string;
  /** Quarantined content is readable as data but cannot be promoted or surfaced as fact. */
  quarantined: boolean;
}

/** A stored memory considered for retrieval. Used by the trust-aware recall filter. */
export interface RecallItem {
  content: string;
  trust: TrustTier;
  capturedAt: string; // ISO 8601, drives temporal decay
  quarantined: boolean;
  hash: string;
}

export type Verdict = "allow" | "quarantine" | "reject";

export interface Decision {
  verdict: Verdict;
  reasons: string[];
}

/** A candidate the DREAMING pipeline wants to write to durable memory. */
export interface PromotionCandidate {
  envelope: Envelope;
  /** Independent corroborating sources already seen, by hash. Used for T2 promotion. */
  corroboration?: { hash: string; trust: TrustTier }[];
  /** True if the write attempts to alter identity/constitution rather than store a fact. */
  touchesIdentity?: boolean;
  /** Promotion target. */
  target: "MEMORY.md" | "chroma" | "obsidian";
}

export interface OutboundAction {
  kind: "message" | "web-post" | "git-push" | "tool-invoke";
  /** The payload that would leave the machine. */
  payload: string;
  /** The originating user goal, for alignment checking on consequential actions. */
  originatingGoal?: string;
  consequential?: boolean;
}

export type LedgerEventKind =
  | "ingress"
  | "promotion"
  | "promotion-rejected"
  | "recall"
  | "soul-write"
  | "soul-write-rejected"
  | "egress"
  | "egress-blocked";

export interface LedgerEntry {
  seq: number;
  at: string; // ISO 8601
  kind: LedgerEventKind;
  /** sha256 hex of the relevant content/subject. */
  subjectHash: string;
  verdict: Verdict;
  reasons: string[];
  meta?: Record<string, string | number | boolean>;
  /** Chain hash linking to the previous entry. */
  prevHash: string;
  entryHash: string;
}

export interface CarapaceConfig {
  /** Per-channel trust ceilings. Maps a ChannelKind to the maximum trust it can ever earn. */
  channelTrust: Record<ChannelKind, TrustTier>;
  /** Files whose mutation requires a signed capability token. */
  protectedFiles: string[];
  /** Minimum trust required to be eligible for promotion to durable memory. */
  promotionFloor: TrustTier;
  /** PEM-encoded Ed25519 public key used to verify capability tokens. The agent never holds the private key. */
  authorityPublicKeyPem: string;
  /** Injection score at or above which content is quarantined. */
  injectionQuarantineThreshold: number;
  /** Trust-aware recall settings. Temporal decay follows arXiv:2601.05504. */
  recall: {
    /** Stored memories below this trust are never surfaced. */
    minTrust: TrustTier;
    /** Half-life in days for recency weighting of recalled memories. */
    halfLifeDays: number;
  };
}

export const DEFAULT_CONFIG: Omit<CarapaceConfig, "authorityPublicKeyPem"> = {
  channelTrust: {
    direct: "T0",
    filesystem: "T1",
    tool: "T1",
    api: "T2",
    web: "T3",
    group: "T3",
    ambient: "T3",
    subagent: "T4",
  },
  protectedFiles: ["SOUL.md", "IDENTITY.md", "AGENTS.md", "BOOTSTRAP.md"],
  promotionFloor: "T2",
  injectionQuarantineThreshold: 0.5,
  recall: { minTrust: "T2", halfLifeDays: 30 },
};
