# Carapace — Claude Code project context

Carapace is a deterministic memory-integrity firewall for memory-first AI agents (TypeScript, ESM, Node >=22). Read `SPEC.md` for the full design and `../HANDOFF.md` for the backlog and working agreements.

## What it does
Five planes plus a ledger: Ingress (tag provenance + score trust), Recall (trust-aware retrieval with temporal decay), Promotion (gate durable-memory writes), Soul (Ed25519 capability tokens enforce protected files), Egress (block secret exfil). Every decision lands in a hash-chained ledger. Trust is a property of provenance, not repetition.

## Verify (must stay green)
```
npm install
npm run typecheck   # tsc --noEmit, strict
npm test            # unit tests across test/, strict
npm run demo        # examples/demo.ts — real crypto + ledger
npm run redteam     # examples/redteam.ts — measured adversarial results
```
The hosted Worker has its own gate in `worker/`: `npm install`, `npm run typecheck`, `npm test`.

## Working agreements
- No fake data, no invented benchmarks. Numbers come from a real run or are attributed to cited prior work (LlamaFirewall, arXiv:2601.05504). The README's "What's real today" section is the honesty contract; keep it true.
- The model detector is now wired in the hosted Worker (`worker/`) via Cloudflare Workers AI, composed with the heuristics behind the `Detector` interface. The verified model is `@cf/meta/llama-guard-3-8b` (the spec's `@cf/meta/llama-prompt-guard-2-86m` is not in the current catalog); the id is configurable via `CARAPACE_MODEL_ID`. The core npm library in `src/` stays heuristic-only and zero-runtime-deps. Real before/after recall is measured (`npm run measure:model` against a Worker with a live AI binding): attack recall 14/30 (46.7%) heuristic-only -> 19/30 (63.3%) heuristic+model, benign false-positive rate 1/25 (4.0%) unchanged.
- The OpenClaw adapter is blocked until ../openclaw-ui-rebuild is built (dist/plugin-sdk types). Do not guess the SDK.
- Strict TS, named exports, no `any`, no em dashes in prose. Small commits.

## Layout
src/{types,provenance,normalize,recall,ledger,capability,soulguard,firewall,index}.ts, src/detectors/{injection,exfil}.ts, test/, examples/.
