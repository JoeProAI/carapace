/**
 * Workers AI model detector.
 *
 * This is the model side of the documented Detector seam. The zero-dependency
 * core library in ../../src stays heuristic-only and never imports a model; the
 * hosted Worker is the surface that has an `env.AI` binding, so the model
 * classifier lives here and is composed with the heuristics through the same
 * `Detector` interface the library already exposes.
 *
 * The model verdict only ever RAISES the injection signal (it can flag content
 * the cheap heuristics miss). It never lowers trust on its own and never
 * touches the promotion gate: promotion still decides on provenance. A model
 * that says "safe" cannot promote untrusted content, and a model that is down
 * or unreachable fails open on detection (the heuristic and the provenance gate
 * remain in force).
 *
 * Model id. The originally-specced classifier was Meta's Prompt Guard 2
 * (`@cf/meta/llama-prompt-guard-2-86m`). That id is not present in the current
 * Workers AI catalog, so the verified default is `@cf/meta/llama-guard-3-8b`,
 * Meta's safety classifier, which the catalog documents as usable for prompt
 * (input) classification. The id is configurable via `CARAPACE_MODEL_ID` so a
 * drop-in guard model can be swapped in without code changes.
 */
import type { Detector, DetectorResult } from "../../src/index.js";

/** Verified Workers AI guard model. Override with the CARAPACE_MODEL_ID var. */
export const DEFAULT_MODEL_ID = "@cf/meta/llama-guard-3-8b";

/** Detector name recorded on the model's DetectorResult. */
const MODEL_DETECTOR_NAME = "workers-ai-guard" as const;

export interface ModelDetectorOptions {
  /** Workers AI model id to call. */
  readonly modelId: string;
  /** Score assigned when the model flags content as unsafe. 0..1. */
  readonly flagScore: number;
  /** Max characters of content sent to the model, to bound cost and latency. */
  readonly maxChars: number;
}

export const DEFAULT_MODEL_OPTIONS: Omit<ModelDetectorOptions, "modelId"> = {
  flagScore: 0.85,
  maxChars: 4000,
};

/** Outcome of one model scan, including whether the model was actually consulted. */
export interface ModelScan {
  /** True if the model produced a usable verdict; false if disabled, skipped, or errored. */
  readonly used: boolean;
  readonly modelId: string;
  /** The verdict as a Detector result. Benign (flagged=false, score=0) when not used. */
  readonly result: DetectorResult;
  /** Present when an attempted call failed; the scan then fails open (used=false). */
  readonly error?: string;
}

const benignResult = (): DetectorResult => ({
  flagged: false,
  score: 0,
  detector: MODEL_DETECTOR_NAME,
  reasons: [],
});

export interface GuardVerdict {
  readonly unsafe: boolean;
  readonly categories: readonly string[];
}

const asRecord = (v: unknown): Record<string, unknown> | undefined =>
  typeof v === "object" && v !== null ? (v as Record<string, unknown>) : undefined;

const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/**
 * Parse a Llama Guard-style response. Two shapes are supported:
 *   - JSON object: { safe: boolean, categories?: string[] }  (response_format json_object)
 *   - plain text:  "safe"  or  "unsafe\nS7"                   (default generation)
 */
export const parseGuardVerdict = (output: Record<string, unknown>): GuardVerdict => {
  const response = output.response;

  const obj = asRecord(response);
  if (obj !== undefined && typeof obj.safe === "boolean") {
    return { unsafe: obj.safe === false, categories: asStringArray(obj.categories) };
  }

  if (typeof response === "string") {
    const lines = response
      .split(/[\n,]+/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const first = (lines[0] ?? "").toLowerCase();
    const unsafe = first.startsWith("unsafe");
    const categories = lines.slice(1).filter((l) => /^s\d{1,2}$/i.test(l));
    return { unsafe, categories };
  }

  // Unrecognized shape: treat as safe, but the caller marks the scan unusable.
  return { unsafe: false, categories: [] };
};

export const verdictToResult = (verdict: GuardVerdict, flagScore: number): DetectorResult => {
  if (!verdict.unsafe) return benignResult();
  const reasons = ["model-flagged-unsafe", ...verdict.categories.map((c) => `model-category:${c}`)];
  return {
    flagged: true,
    score: Number(flagScore.toFixed(3)),
    detector: MODEL_DETECTOR_NAME,
    reasons,
  };
};

/**
 * Run the Workers AI guard model over a piece of content and return a verdict.
 * Never throws: a missing binding, unknown response, or runtime error yields a
 * fail-open scan (used=false, benign result) so the heuristic and provenance
 * gate stay load-bearing.
 */
export const runModelGuard = async (
  ai: Ai | undefined,
  content: string,
  options: ModelDetectorOptions,
): Promise<ModelScan> => {
  if (ai === undefined) {
    return { used: false, modelId: options.modelId, result: benignResult() };
  }
  const text = content.length > options.maxChars ? content.slice(0, options.maxChars) : content;
  try {
    const output = await ai.run(options.modelId, {
      messages: [{ role: "user", content: text }],
      response_format: { type: "json_object" },
    });
    const record = asRecord(output);
    if (record === undefined || !("response" in record)) {
      return { used: false, modelId: options.modelId, result: benignResult(), error: "unrecognized-model-output" };
    }
    const verdict = parseGuardVerdict(record);
    return { used: true, modelId: options.modelId, result: verdictToResult(verdict, options.flagScore) };
  } catch (err) {
    const error = err instanceof Error ? err.message : "model-call-failed";
    return { used: false, modelId: options.modelId, result: benignResult(), error };
  }
};

/**
 * Wrap an already-computed model verdict as a synchronous Detector. The core
 * `Detector.scan` is sync (it runs on the deterministic hot path); the model
 * call is async, so the Worker runs it first and injects the precomputed result
 * here. This is how an async model joins the sync composite without the core
 * library learning anything about Workers AI.
 */
export const precomputedDetector = (result: DetectorResult): Detector => ({
  name: result.detector,
  scan: () => result,
});

/** Build model-detector options from Worker env, falling back to verified defaults. */
export const modelOptionsFromEnv = (modelId: string | undefined): ModelDetectorOptions => ({
  modelId: modelId !== undefined && modelId.length > 0 ? modelId : DEFAULT_MODEL_ID,
  ...DEFAULT_MODEL_OPTIONS,
});
