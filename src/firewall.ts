import type {
  CarapaceConfig,
  Decision,
  Envelope,
  OutboundAction,
  PromotionCandidate,
  Provenance,
  RecallItem,
  Detector,
} from "./types.js";
import { atLeast, deriveTrust } from "./provenance.js";
import { combineInjectionResults, heuristicInjectionDetector } from "./detectors/injection.js";
import { scanExfil } from "./detectors/exfil.js";
import { Ledger } from "./ledger.js";
import { SoulGuard } from "./soulguard.js";
import { sha256 } from "./hash.js";
import { filterRecall as filterRecallItems, type FilterResult } from "./recall.js";

export interface CarapaceDeps {
  ledger?: Ledger;
  soulguard?: SoulGuard;
  /** Filenames that must never leave the machine, matched literally on egress. */
  secretRegistry?: readonly string[];
  /** Extra orthogonal ingress detectors merged with the built-in heuristic (e.g. a model classifier). */
  detectors?: readonly Detector[];
}

/**
 * The orchestrator. Each method is a checkpoint on a path data already travels
 * in OpenClaw. Every decision is written to the ledger.
 */
export class Carapace {
  readonly config: CarapaceConfig;
  readonly ledger: Ledger;
  private readonly soulguard: SoulGuard | undefined;
  private readonly secretRegistry: readonly string[];
  private readonly extraDetectors: readonly Detector[];
  private readonly reviewQueue: { candidate: PromotionCandidate; reasons: string[] }[] = [];

  constructor(config: CarapaceConfig, deps: CarapaceDeps = {}) {
    this.config = config;
    this.ledger = deps.ledger ?? new Ledger();
    this.soulguard = deps.soulguard;
    this.secretRegistry = deps.secretRegistry ?? [];
    this.extraDetectors = deps.detectors ?? [];
  }

  /** Plane 1: wrap inbound content, score it, quarantine if hostile. */
  ingress(content: string, provenance: Provenance): Envelope {
    const trust = deriveTrust(provenance, this.config);
    const injection = combineInjectionResults([
      heuristicInjectionDetector.scan(content, provenance),
      ...this.extraDetectors.map((d) => d.scan(content, provenance)),
    ]);
    const exfil = scanExfil(content, this.secretRegistry);
    const hash = sha256(content);
    const quarantined = injection.flagged || injection.score >= this.config.injectionQuarantineThreshold;

    const envelope: Envelope = {
      content,
      provenance,
      trust,
      scan: { injection, exfil },
      hash,
      quarantined,
    };

    this.ledger.append(
      "ingress",
      hash,
      { verdict: quarantined ? "quarantine" : "allow", reasons: quarantined ? injection.reasons : [] },
      { trust, channel: provenance.channel, source: provenance.source, injectionScore: injection.score },
    );

    return envelope;
  }

  /** Plane 3: the gate. Decide whether a candidate may become durable memory. */
  canPromote(candidate: PromotionCandidate): Decision {
    const env = candidate.envelope;
    const reasons: string[] = [];

    if (candidate.touchesIdentity) {
      reasons.push("promotion-cannot-alter-identity-route-through-soulguard");
    }
    if (env.quarantined) {
      reasons.push("quarantined-content-ineligible");
    }
    if (env.scan.injection.flagged) {
      reasons.push("active-injection-flag");
    }
    if (!atLeast(env.trust, this.config.promotionFloor)) {
      reasons.push(`below-promotion-floor:${env.trust}<${this.config.promotionFloor}`);
    }
    if (env.trust === "T2") {
      const corroborated = (candidate.corroboration ?? []).filter((c) => atLeast(c.trust, "T1"));
      if (corroborated.length === 0) {
        reasons.push("t2-requires-independent-t1-corroboration");
      }
    }

    const decision: Decision =
      reasons.length === 0 ? { verdict: "allow", reasons: ["passed-promotion-gate"] } : { verdict: "reject", reasons };

    if (decision.verdict === "reject") {
      this.reviewQueue.push({ candidate, reasons });
    }
    this.ledger.append(decision.verdict === "allow" ? "promotion" : "promotion-rejected", env.hash, decision, {
      trust: env.trust,
      target: candidate.target,
    });

    return decision;
  }

  /** Plane 5: stop secrets leaving, flag goal-divergent consequential actions. */
  checkEgress(action: OutboundAction): Decision {
    const exfil = scanExfil(action.payload, this.secretRegistry);
    if (exfil.flagged) {
      const decision: Decision = { verdict: "reject", reasons: ["outbound-contains-secrets", ...exfil.reasons] };
      this.ledger.append("egress-blocked", sha256(action.payload), decision, { kind: action.kind });
      return decision;
    }

    if (action.consequential && action.originatingGoal === undefined) {
      const decision: Decision = { verdict: "quarantine", reasons: ["consequential-action-without-stated-goal"] };
      this.ledger.append("egress", sha256(action.payload), decision, { kind: action.kind });
      return decision;
    }

    const decision: Decision = { verdict: "allow", reasons: [] };
    this.ledger.append("egress", sha256(action.payload), decision, { kind: action.kind });
    return decision;
  }

  /** Plane 4: protected-file writes need a signed capability. Fails closed. */
  guardSoulWrite(path: string, newContent: string, token?: string): Decision {
    const isProtected = this.config.protectedFiles.includes(path);
    let decision: Decision;

    if (!isProtected) {
      decision = { verdict: "allow", reasons: ["not-a-protected-file"] };
    } else if (!this.soulguard) {
      decision = { verdict: "reject", reasons: ["soulguard-not-configured", "fail-closed"] };
    } else {
      decision = this.soulguard.authorizeWrite(path, newContent, token);
    }

    this.ledger.append(
      decision.verdict === "allow" ? "soul-write" : "soul-write-rejected",
      sha256(`${path}:${newContent}`),
      decision,
      { path },
    );
    return decision;
  }

  /** Plane 2: trust-aware retrieval with temporal decay and pattern filtering. */
  filterRecall(items: readonly RecallItem[], now?: number): FilterResult {
    const result = filterRecallItems(items, this.config, now);
    const subject = sha256(items.map((i) => i.hash).join("|"));
    this.ledger.append("recall", subject, {
      verdict: "allow",
      reasons: [`kept:${result.kept.length}`, `dropped:${result.dropped.length}`],
    });
    return result;
  }

  /** Rejected promotions waiting for human review. */
  pendingReview(): readonly { candidate: PromotionCandidate; reasons: string[] }[] {
    return this.reviewQueue;
  }
}
