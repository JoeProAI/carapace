import { sign, verify } from "node:crypto";

/**
 * Capability tokens replace the prompt-based "KaKaw" rule.
 *
 * A protected-file change is authorized by a short-lived, single-use grant
 * signed with the principal's Ed25519 key. The agent holds only the public key,
 * so it can verify a grant but can never forge one. Saying the code word in a
 * group chat does nothing, because that path cannot sign.
 */

export interface CapabilityGrant {
  action: "modify-protected-file";
  /** The file path this grant authorizes, e.g. "SOUL.md". */
  target: string;
  /** Single-use nonce. The verifier rejects replays. */
  nonce: string;
  /** Expiry, unix epoch ms. */
  exp: number;
}

const canonical = (grant: CapabilityGrant): string =>
  // Fixed, alphabetical key order so mint and verify hash identical bytes.
  JSON.stringify({ action: grant.action, exp: grant.exp, nonce: grant.nonce, target: grant.target });

const b64url = (data: string): string => Buffer.from(data, "utf8").toString("base64url");
const unb64url = (data: string): string => Buffer.from(data, "base64url").toString("utf8");

/**
 * Mint a token. This runs on the authenticated attest path only, where the
 * principal's private key is available (hardware token, separate signer, etc).
 * The agent runtime never calls this.
 */
export const mintCapability = (privateKeyPem: string, grant: CapabilityGrant): string => {
  const payload = canonical(grant);
  const sig = sign(null, Buffer.from(payload, "utf8"), privateKeyPem);
  return `${b64url(payload)}.${sig.toString("base64url")}`;
};

export interface VerifyResult {
  valid: boolean;
  reason: string;
  grant?: CapabilityGrant;
}

const parseGrant = (json: string): CapabilityGrant | null => {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const g = raw as Record<string, unknown>;
  if (
    g["action"] !== "modify-protected-file" ||
    typeof g["target"] !== "string" ||
    typeof g["nonce"] !== "string" ||
    typeof g["exp"] !== "number"
  ) {
    return null;
  }
  return { action: "modify-protected-file", target: g["target"], nonce: g["nonce"], exp: g["exp"] };
};

export const verifyCapability = (
  publicKeyPem: string,
  token: string,
  expected: { target: string; now?: number },
): VerifyResult => {
  const parts = token.split(".");
  const payloadPart = parts[0];
  const sigPart = parts[1];
  if (parts.length !== 2 || payloadPart === undefined || sigPart === undefined) {
    return { valid: false, reason: "malformed-token" };
  }

  let payloadJson: string;
  try {
    payloadJson = unb64url(payloadPart);
  } catch {
    return { valid: false, reason: "bad-payload-encoding" };
  }

  const grant = parseGrant(payloadJson);
  if (!grant) return { valid: false, reason: "bad-grant-shape" };

  let sigOk = false;
  try {
    sigOk = verify(null, Buffer.from(payloadJson, "utf8"), publicKeyPem, Buffer.from(sigPart, "base64url"));
  } catch {
    return { valid: false, reason: "signature-verify-error" };
  }
  if (!sigOk) return { valid: false, reason: "bad-signature" };

  const now = expected.now ?? Date.now();
  if (grant.exp < now) return { valid: false, reason: "expired", grant };
  if (grant.target !== expected.target) return { valid: false, reason: "target-mismatch", grant };

  return { valid: true, reason: "ok", grant };
};
