import type { Decision } from "./types.js";
import { GENESIS, sha256 } from "./hash.js";
import { verifyCapability } from "./capability.js";

export interface ProtectedFile {
  path: string;
  content: string;
}

/**
 * Enforces integrity of the agent's constitution (SOUL.md, IDENTITY.md, etc).
 *
 * On init it records a hash of each protected file and chains them into a single
 * head. Any write must present a valid, unused, non-expired capability token that
 * targets that exact file. Unauthorized writes are rejected and should be rolled
 * back by the caller to the last good content.
 */
export class SoulGuard {
  private readonly fileHashes = new Map<string, string>();
  private chainHead: string = GENESIS;
  private readonly usedNonces = new Set<string>();
  private readonly authorityPublicKeyPem: string;

  constructor(files: ProtectedFile[], authorityPublicKeyPem: string) {
    this.authorityPublicKeyPem = authorityPublicKeyPem;
    for (const f of files) this.fileHashes.set(f.path, sha256(f.content));
    this.chainHead = this.recompute();
  }

  /** Deterministic chain over protected files, sorted by path. */
  private recompute(): string {
    const paths = [...this.fileHashes.keys()].sort();
    let acc = GENESIS;
    for (const p of paths) {
      acc = sha256(`${this.fileHashes.get(p) ?? ""}|${acc}`);
    }
    return acc;
  }

  head(): string {
    return this.chainHead;
  }

  /** Compare current on-disk content against the recorded baseline. Detects out-of-band tampering. */
  verifyIntegrity(current: ProtectedFile[]): { valid: boolean; drifted: string[] } {
    const drifted: string[] = [];
    for (const f of current) {
      const known = this.fileHashes.get(f.path);
      if (known === undefined) continue;
      if (sha256(f.content) !== known) drifted.push(f.path);
    }
    return { valid: drifted.length === 0, drifted };
  }

  /**
   * Authorize (and, if allowed, record) a write to a protected file.
   * Returns a Decision. On allow, the baseline advances to the new content.
   */
  authorizeWrite(path: string, newContent: string, token?: string, now?: number): Decision {
    if (!this.fileHashes.has(path)) {
      // Not protected. Caller should route this through the normal growth-file path.
      return { verdict: "allow", reasons: ["not-a-protected-file"] };
    }
    if (token === undefined) {
      return { verdict: "reject", reasons: ["no-capability-token", "protected-file"] };
    }

    const expected = now === undefined ? { target: path } : { target: path, now };
    const res = verifyCapability(this.authorityPublicKeyPem, token, expected);
    if (!res.valid || !res.grant) {
      return { verdict: "reject", reasons: [`capability-${res.reason}`] };
    }
    if (this.usedNonces.has(res.grant.nonce)) {
      return { verdict: "reject", reasons: ["nonce-replayed"] };
    }

    this.usedNonces.add(res.grant.nonce);
    this.fileHashes.set(path, sha256(newContent));
    this.chainHead = this.recompute();
    return { verdict: "allow", reasons: ["valid-capability", `nonce:${res.grant.nonce}`] };
  }
}
