/**
 * Mem0 drop-in adapter.
 *
 * Wraps a Mem0 client so every memory write passes through the Carapace
 * promotion gate before it is stored. Untrusted content (web, tool output,
 * sub-agents) is rejected at the gate and never reaches durable memory, while
 * first-party principal input flows through unchanged. The wrapper is
 * transparent: it returns the same client type with `add` gated and every other
 * method delegated, so existing code keeps working.
 *
 *   import MemoryClient from "mem0ai";
 *   import { withCarapace, localGate } from "@openclaw/carapace/adapters/mem0";
 *
 *   const memory = withCarapace(new MemoryClient({ apiKey }), { gate: localGate() });
 *   await memory.add(messages, { user_id: "u1" }); // gated, then stored
 *
 * To run the gate as a hosted service instead of in-process, swap localGate()
 * for remoteGate({ apiKey, host }) pointed at the Carapace Worker.
 *
 * Honest scope. Carapace gates on provenance, and only the integrator knows the
 * true provenance of each message. The role defaults below assume the `user`
 * role is the trusted principal and `assistant` is first-party tool output. In
 * a multi-user or adversarial-user setting you MUST label untrusted messages
 * with their real channel (pass `carapaceProvenance` per call); otherwise the
 * heuristic detector becomes the only backstop, and a heuristic detector is not
 * a guarantee. The adapter gates writes only: search/get/update/delete pass
 * through unchanged.
 */
import { generateKeyPairSync } from "node:crypto";
import { createCarapace } from "../index.js";
import {
  DEFAULT_CONFIG,
  type CarapaceConfig,
  type ChannelKind,
  type Decision,
  type PromotionCandidate,
  type Provenance,
  type TrustTier,
  type Verdict,
} from "../types.js";

/**
 * A memory message in the Mem0 shape. Structurally matches mem0ai's `Message`
 * so the adapter never has to import mem0ai (zero runtime dependencies).
 */
export interface Mem0Message {
  role: "user" | "assistant";
  content: string | { type: "image_url"; image_url: { url: string } };
}

/**
 * The minimal Mem0 surface the adapter needs. Both the hosted `MemoryClient`
 * and the OSS `Memory` class from mem0ai satisfy this structurally.
 */
export interface Mem0AddCapable {
  add(messages: Mem0Message[], options?: Record<string, unknown>): Promise<unknown>;
}

/** Promotion target recorded in the ledger. Mirrors `PromotionCandidate["target"]`. */
export type PromotionTarget = PromotionCandidate["target"];

/** Independent corroborating sources used for T2 promotion. */
export type Corroboration = { hash: string; trust: TrustTier }[];

/** The verdict for a single gated message. */
export interface GateDecision {
  /** `allow` means "store it". `reject` means "drop it". */
  verdict: Verdict;
  reasons: string[];
  trust: TrustTier;
  quarantined: boolean;
  /** sha256 of the gated content, hex. */
  hash: string;
}

/** Input to a gate evaluation. */
export interface GateInput {
  content: string;
  provenance: Provenance;
  target: PromotionTarget;
  corroboration?: Corroboration;
  touchesIdentity?: boolean;
}

/**
 * A promotion gate. `localGate()` runs the firewall in-process; `remoteGate()`
 * calls the hosted Carapace Worker. Both return the same decision shape.
 */
export interface CarapaceGate {
  evaluate(input: GateInput): Promise<GateDecision>;
}

/** Provenance defaults applied per message role before gating. */
export interface ProvenanceDefaults {
  source: string;
  channel: ChannelKind;
  authenticated: boolean;
  actor?: string;
}

/** Per-role provenance defaults. */
export interface RoleProvenance {
  user: ProvenanceDefaults;
  assistant: ProvenanceDefaults;
}

/**
 * Default role provenance. `user` is treated as the authenticated principal on a
 * direct channel (T0); `assistant` as first-party tool output (T1). Override
 * per call with `carapaceProvenance` for untrusted sources.
 */
export const DEFAULT_ROLE_PROVENANCE: RoleProvenance = {
  user: { source: "mem0:user", channel: "direct", authenticated: true },
  assistant: { source: "mem0:assistant", channel: "tool", authenticated: true },
};

/** Options for `withCarapace`. */
export interface WithCarapaceOptions {
  gate: CarapaceGate;
  /** Promotion target recorded in the ledger. Defaults to "chroma" (Mem0's vector store). */
  target?: PromotionTarget;
  /** Per-role provenance defaults. Defaults to `DEFAULT_ROLE_PROVENANCE`. */
  roleProvenance?: RoleProvenance;
  /** Observability hook fired for every gated message. */
  onDecision?: (event: { message: Mem0Message; decision: GateDecision }) => void;
}

/**
 * Per-call controls. Pass these inside the `add` options object; they are
 * stripped before the options are forwarded to the underlying client.
 */
export interface CarapaceAddExtras {
  /** Override provenance for every message in this call (e.g. scraped web content). */
  carapaceProvenance?: Partial<Provenance>;
  /** Independent corroborating sources, for T2 promotion. */
  carapaceCorroboration?: Corroboration;
  /** Mark this write as identity-altering (always rejected by the gate). */
  carapaceTouchesIdentity?: boolean;
}

/** Options for `localGate`. */
export interface LocalGateOptions {
  /** Config overrides merged onto `DEFAULT_CONFIG`. */
  config?: Partial<Omit<CarapaceConfig, "authorityPublicKeyPem">>;
  /**
   * PEM Ed25519 public key for capability verification. The promotion gate does
   * not exercise capabilities, so this is optional; if omitted an ephemeral key
   * is generated per gate instance.
   */
  authorityPublicKeyPem?: string;
}

/** Options for `remoteGate`. */
export interface RemoteGateOptions {
  /** API key for the hosted Carapace Worker (sent as `Authorization: Bearer`). */
  apiKey: string;
  /** Base URL of the Worker, e.g. `https://carapace.example.workers.dev`. */
  host: string;
  /** Override the fetch implementation (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const messageText = (message: Mem0Message): string =>
  typeof message.content === "string" ? message.content : message.content.image_url.url;

const generateEphemeralPublicKeyPem = (): string => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" });
  return typeof pem === "string" ? pem : pem.toString("utf8");
};

const buildProvenance = (base: ProvenanceDefaults, override?: Partial<Provenance>): Provenance => {
  const channel = override?.channel ?? base.channel;
  const source = override?.source ?? base.source;
  const authenticated = override?.authenticated ?? base.authenticated;
  const actor = override?.actor ?? base.actor;
  const provenance: Provenance = {
    source,
    channel,
    authenticated,
    capturedAt: override?.capturedAt ?? new Date().toISOString(),
  };
  if (actor !== undefined) {
    provenance.actor = actor;
  }
  return provenance;
};

interface Extras {
  provenance?: Partial<Provenance>;
  corroboration?: Corroboration;
  touchesIdentity?: boolean;
}

const extractExtras = (options?: Record<string, unknown>): Extras => {
  if (options === undefined) {
    return {};
  }
  const extras: Extras = {};
  const provenance = options["carapaceProvenance"];
  if (isRecord(provenance)) {
    extras.provenance = provenance as Partial<Provenance>;
  }
  const corroboration = options["carapaceCorroboration"];
  if (Array.isArray(corroboration)) {
    extras.corroboration = corroboration as Corroboration;
  }
  const touchesIdentity = options["carapaceTouchesIdentity"];
  if (typeof touchesIdentity === "boolean") {
    extras.touchesIdentity = touchesIdentity;
  }
  return extras;
};

const stripExtras = (options?: Record<string, unknown>): Record<string, unknown> | undefined => {
  if (options === undefined) {
    return undefined;
  }
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(options)) {
    if (key === "carapaceProvenance" || key === "carapaceCorroboration" || key === "carapaceTouchesIdentity") {
      continue;
    }
    rest[key] = value;
  }
  return rest;
};

const gatedAdd = async (
  target: Mem0AddCapable,
  options: WithCarapaceOptions,
  messages: Mem0Message[],
  addOptions?: Record<string, unknown>,
): Promise<unknown> => {
  const roleProvenance = options.roleProvenance ?? DEFAULT_ROLE_PROVENANCE;
  const promotionTarget: PromotionTarget = options.target ?? "chroma";
  const extras = extractExtras(addOptions);
  const forwarded = stripExtras(addOptions);

  const survivors: Mem0Message[] = [];
  for (const message of messages) {
    const provenance = buildProvenance(roleProvenance[message.role], extras.provenance);
    const input: GateInput = {
      content: messageText(message),
      provenance,
      target: promotionTarget,
    };
    if (extras.corroboration !== undefined) {
      input.corroboration = extras.corroboration;
    }
    if (extras.touchesIdentity !== undefined) {
      input.touchesIdentity = extras.touchesIdentity;
    }
    const decision = await options.gate.evaluate(input);
    options.onDecision?.({ message, decision });
    if (decision.verdict === "allow") {
      survivors.push(message);
    }
  }

  if (survivors.length === 0) {
    return [];
  }
  return target.add(survivors, forwarded);
};

/**
 * Wrap a Mem0 client so writes are gated by Carapace. Returns the same client
 * type: `add` is gated, every other method (search, get, update, delete, ...)
 * is delegated untouched.
 */
export function withCarapace<T extends Mem0AddCapable>(client: T, options: WithCarapaceOptions): T {
  const handler: ProxyHandler<T> = {
    get(target, prop, receiver) {
      if (prop === "add") {
        return (messages: Mem0Message[], addOptions?: Record<string, unknown>): Promise<unknown> =>
          gatedAdd(target, options, messages, addOptions);
      }
      const value: unknown = Reflect.get(target, prop, receiver);
      if (typeof value === "function") {
        return (value as (...args: unknown[]) => unknown).bind(target);
      }
      return value;
    },
  };
  return new Proxy(client, handler);
}

/**
 * A gate that runs the Carapace firewall in-process. Deterministic, no network,
 * no API key. The firewall instance is built lazily on first use.
 */
export function localGate(options: LocalGateOptions = {}): CarapaceGate {
  let extension: ReturnType<typeof createCarapace> | undefined;
  const build = (): ReturnType<typeof createCarapace> => {
    if (extension === undefined) {
      const authorityPublicKeyPem = options.authorityPublicKeyPem ?? generateEphemeralPublicKeyPem();
      const config: CarapaceConfig = { ...DEFAULT_CONFIG, ...options.config, authorityPublicKeyPem };
      extension = createCarapace(config);
    }
    return extension;
  };
  return {
    evaluate(input: GateInput): Promise<GateDecision> {
      const carapace = build();
      const envelope = carapace.onIngress({ content: input.content, provenance: input.provenance });
      const candidate: PromotionCandidate = { envelope, target: input.target };
      if (input.corroboration !== undefined) {
        candidate.corroboration = input.corroboration;
      }
      if (input.touchesIdentity !== undefined) {
        candidate.touchesIdentity = input.touchesIdentity;
      }
      const decision: Decision = carapace.onMemoryWrite(candidate);
      return Promise.resolve({
        verdict: decision.verdict,
        reasons: decision.reasons,
        trust: envelope.trust,
        quarantined: envelope.quarantined,
        hash: envelope.hash,
      });
    },
  };
}

interface PromoteResponse {
  verdict: Verdict;
  reasons: string[];
  trust: TrustTier;
  quarantined: boolean;
  hash: string;
}

/**
 * A gate that calls the hosted Carapace Worker's `POST /v1/promote` endpoint.
 * Use this to gate writes without embedding the firewall.
 */
export function remoteGate(options: RemoteGateOptions): CarapaceGate {
  const base = options.host.replace(/\/+$/, "");
  const doFetch = options.fetchImpl ?? fetch;
  return {
    async evaluate(input: GateInput): Promise<GateDecision> {
      const body: Record<string, unknown> = {
        content: input.content,
        provenance: input.provenance,
        target: input.target,
      };
      if (input.corroboration !== undefined) {
        body["corroboration"] = input.corroboration;
      }
      if (input.touchesIdentity !== undefined) {
        body["touchesIdentity"] = input.touchesIdentity;
      }
      const response = await doFetch(`${base}/v1/promote`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${options.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error(`carapace gate returned ${response.status}`);
      }
      const data = (await response.json()) as PromoteResponse;
      return {
        verdict: data.verdict,
        reasons: data.reasons,
        trust: data.trust,
        quarantined: data.quarantined,
        hash: data.hash,
      };
    },
  };
}
