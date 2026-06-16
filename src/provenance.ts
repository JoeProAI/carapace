import type { CarapaceConfig, Provenance, TrustTier } from "./types.js";
import { trustRank } from "./types.js";

/**
 * Derive a trust tier from provenance.
 *
 * The rule is deliberately conservative: a channel can only ever lower trust,
 * never raise it. An authenticated direct channel from the principal is the
 * only path to T0, and even then the actor must read as the principal.
 */
export const deriveTrust = (prov: Provenance, config: CarapaceConfig): TrustTier => {
  const ceiling = config.channelTrust[prov.channel];

  // The only path to T0 is an authenticated direct channel whose actor is the principal.
  if (ceiling === "T0") {
    const isPrincipal = prov.authenticated === true && (prov.actor === undefined || prov.actor === "joe");
    return isPrincipal ? "T0" : "T2";
  }

  // Everything else is capped at its channel ceiling. Unauthenticated drops one tier.
  if (prov.authenticated === false) {
    return lower(ceiling);
  }
  return ceiling;
};

/** Drop a tier toward less trust. T4 is the floor. */
export const lower = (tier: TrustTier): TrustTier => {
  const order: TrustTier[] = ["T0", "T1", "T2", "T3", "T4"];
  const idx = order.indexOf(tier);
  return order[Math.min(idx + 1, order.length - 1)] ?? "T4";
};

/** True if `a` is at least as trusted as `b`. */
export const atLeast = (a: TrustTier, b: TrustTier): boolean => trustRank(a) >= trustRank(b);
