/**
 * Measurement helpers. No results are hardcoded; these only time and count.
 */
import { createCarapace, DEFAULT_CONFIG, type CarapaceConfig, type Provenance } from "../src/index.js";
import { generateKeyPairSync } from "node:crypto";

/** Build a configured firewall with a real Ed25519 authority key and a secret registry. */
export const buildFirewall = (): ReturnType<typeof createCarapace> => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const config: CarapaceConfig = {
    ...DEFAULT_CONFIG,
    authorityPublicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
  return createCarapace(config, { secretRegistry: [".env", "id_rsa", "credentials.json"] });
};

export const provenance = (
  channel: Provenance["channel"],
  authenticated = false,
): Provenance => ({
  source: `${channel}:bench`,
  channel,
  authenticated,
  capturedAt: new Date().toISOString(),
});

/** First-party channels: the principal's own direct input and the agent's own files/tools. */
const FIRST_PARTY: ReadonlySet<Provenance["channel"]> = new Set(["direct", "filesystem", "tool"]);

/**
 * Realistic provenance for a benign item: first-party channels are
 * authenticated (it is the principal or the agent's own machine); third-party
 * channels (web, api, group, ...) are not. Attacks never get authentication.
 */
export const benignProvenance = (channel: Provenance["channel"]): Provenance =>
  provenance(channel, FIRST_PARTY.has(channel));

/** Exact percentile (nearest-rank) over a numeric sample, in the sample's units. */
export const percentile = (sortedAsc: readonly number[], p: number): number => {
  if (sortedAsc.length === 0) return 0;
  const rank = Math.ceil((p / 100) * sortedAsc.length);
  const idx = Math.min(sortedAsc.length - 1, Math.max(0, rank - 1));
  return sortedAsc[idx] as number;
};

export const mean = (xs: readonly number[]): number =>
  xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length;

/** Time a function `iterations` times, returning per-call nanoseconds sorted ascending. */
export const timeNs = (fn: () => void, iterations: number, warmup: number): number[] => {
  for (let i = 0; i < warmup; i += 1) fn();
  const samples = new Array<number>(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    samples[i] = Number(t1 - t0);
  }
  return samples.sort((a, b) => a - b);
};

export const pct = (n: number, d: number): string =>
  d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`;

export const nsToMs = (ns: number): string => (ns / 1_000_000).toFixed(4);

export const nsToUs = (ns: number): string => (ns / 1_000).toFixed(2);
