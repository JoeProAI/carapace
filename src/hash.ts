import { createHash } from "node:crypto";

/** sha256 of a utf8 string, hex-encoded. */
export const sha256 = (data: string): string => createHash("sha256").update(data, "utf8").digest("hex");

/** Genesis hash for chain heads. */
export const GENESIS = "0".repeat(64);
