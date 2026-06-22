import { Carapace } from "./firewall.js";
import { Ledger } from "./ledger.js";
import { SoulGuard, type ProtectedFile } from "./soulguard.js";
import type { CarapaceConfig, Detector, LedgerEntry, OutboundAction, PromotionCandidate, Provenance, RecallItem } from "./types.js";

/**
 * OpenClaw extension entry.
 *
 * This returns typed handlers rather than coupling to a host API surface. A thin
 * adapter binds them to OpenClaw hooks (memory.write, memory.search, file.write,
 * message.send, tool.invoke) the same way the lobster plugin binds its tool.
 * See README for the wiring contract.
 */

export interface ToolInput {
  action: string;
  args?: Record<string, unknown>;
}

export interface CreateCarapaceOptions {
  /** Initial content of protected files, for the soul-integrity baseline. */
  protectedFiles?: ProtectedFile[];
  /** Filenames that must never leave the machine. */
  secretRegistry?: readonly string[];
  /** Sink for ledger entries, e.g. append to carapace.ledger on disk. */
  persistLedger?: (entry: LedgerEntry) => void;
  /**
   * Extra orthogonal ingress detectors merged with the built-in heuristic. This
   * is the documented seam: a model classifier (e.g. a Workers AI guard) lives
   * outside this zero-dependency core and is injected here as a Detector. The
   * core never imports or depends on any model.
   */
  detectors?: readonly Detector[];
}

export interface CarapaceExtension {
  firewall: Carapace;
  onIngress: (e: { content: string; provenance: Provenance }) => ReturnType<Carapace["ingress"]>;
  onMemoryWrite: (candidate: PromotionCandidate) => ReturnType<Carapace["canPromote"]>;
  onRecall: (items: readonly RecallItem[]) => ReturnType<Carapace["filterRecall"]>;
  onFileWrite: (e: { path: string; content: string; token?: string }) => ReturnType<Carapace["guardSoulWrite"]>;
  onMessageSend: (action: OutboundAction) => ReturnType<Carapace["checkEgress"]>;
  tool: { name: "carapace"; run: (input: ToolInput) => unknown };
}

export const createCarapace = (config: CarapaceConfig, options: CreateCarapaceOptions = {}): CarapaceExtension => {
  const ledger = new Ledger(options.persistLedger);
  const soulguard =
    options.protectedFiles && options.protectedFiles.length > 0
      ? new SoulGuard(options.protectedFiles, config.authorityPublicKeyPem)
      : undefined;

  const firewall = new Carapace(config, {
    ledger,
    ...(soulguard ? { soulguard } : {}),
    ...(options.secretRegistry ? { secretRegistry: options.secretRegistry } : {}),
    ...(options.detectors ? { detectors: options.detectors } : {}),
  });

  const tool = {
    name: "carapace" as const,
    run: (input: ToolInput): unknown => {
      switch (input.action) {
        case "status":
          return {
            ledgerHead: firewall.ledger.head(),
            entries: firewall.ledger.all().length,
            pendingReview: firewall.pendingReview().length,
            soulguard: soulguard ? "configured" : "disabled",
          };
        case "verify":
          return firewall.ledger.verify();
        case "review":
          return firewall.pendingReview();
        case "attest":
          return {
            ok: false,
            message:
              "Capability tokens are minted on the authenticated signer that holds the principal's private key, not by the agent. Run the attest CLI on Joe's side and pass the token to file.write.",
          };
        default:
          return { error: `unknown action: ${input.action}`, actions: ["status", "verify", "review", "attest"] };
      }
    },
  };

  return {
    firewall,
    onIngress: (e) => firewall.ingress(e.content, e.provenance),
    onMemoryWrite: (candidate) => firewall.canPromote(candidate),
    onRecall: (items) => firewall.filterRecall(items),
    onFileWrite: (e) => firewall.guardSoulWrite(e.path, e.content, e.token),
    onMessageSend: (action) => firewall.checkEgress(action),
    tool,
  };
};

export default createCarapace;

export { Carapace } from "./firewall.js";
export { Ledger } from "./ledger.js";
export { SoulGuard } from "./soulguard.js";
export { mintCapability, verifyCapability } from "./capability.js";
export { scanInjection } from "./detectors/injection.js";
export { scanExfil } from "./detectors/exfil.js";
export { filterRecall, recallScore, recencyWeight } from "./recall.js";
export { deriveTrust, atLeast } from "./provenance.js";
export * from "./types.js";
