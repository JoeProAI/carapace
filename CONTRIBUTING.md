# Contributing to Carapax

Carapax (npm package `@openclaw/carapace`) is the memory-integrity firewall for memory-first AI agents. Contributions are welcome. This guide covers the local setup and the rules that keep the project honest and deterministic.

## Setup

Requires Node >=22.

```
npm install
```

The hosted Worker has its own workspace:

```
cd worker && npm install
```

## Verify gate (must stay green)

Run these before opening a pull request. CI runs the same checks.

```
npm run typecheck   # tsc --noEmit, strict
npm test            # vitest, strict
npm run demo        # real crypto + ledger
npm run redteam     # measured adversarial results
npm run bench       # heuristic vs model recall on the corpus
```

Worker gate:

```
cd worker && npm run typecheck && npm test
```

## Rules

- No fake data and no invented benchmarks. Every number comes from a real run or is attributed to cited prior work. The README "What's real today" section is the honesty contract; keep it true.
- Strict TypeScript. Named exports only. No `any`.
- No em dashes in prose, no emoji.
- Small, focused commits with clear messages.
- The core library in `src/` stays zero-runtime-deps (`node:crypto` only). Model-based detection lives in the Worker, not the core.
- Do not change the core invariant: the model verdict raises the injection signal, but the promotion gate decides on provenance.

## Reporting security issues

Do not open public issues for vulnerabilities. See `SECURITY.md`.
