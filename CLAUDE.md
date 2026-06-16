# Carapace — Claude Code project context

Carapace is a deterministic memory-integrity firewall for memory-first AI agents (TypeScript, ESM, Node >=22). Read `SPEC.md` for the full design and `../HANDOFF.md` for the backlog and working agreements.

## What it does
Five planes plus a ledger: Ingress (tag provenance + score trust), Recall (trust-aware retrieval with temporal decay), Promotion (gate durable-memory writes), Soul (Ed25519 capability tokens enforce protected files), Egress (block secret exfil). Every decision lands in a hash-chained ledger. Trust is a property of provenance, not repetition.

## Verify (must stay green)
```
npm install
npm run typecheck   # tsc --noEmit, strict
npm test            # 33 tests across test/carapace.test.ts and test/adversarial.test.ts
npm run demo        # examples/demo.ts — real crypto + ledger
npm run redteam     # examples/redteam.ts — measured adversarial results
```

## Working agreements
- No fake data, no invented benchmarks. Numbers come from a real run or are attributed to cited prior work (LlamaFirewall, arXiv:2601.05504). The README's "What's real today" section is the honesty contract; keep it true.
- The model detector (PromptGuard 2) is a documented seam behind the `Detector` interface, not built. If you implement it, report measured before/after on the redteam corpus.
- The OpenClaw adapter is blocked until ../openclaw-ui-rebuild is built (dist/plugin-sdk types). Do not guess the SDK.
- Strict TS, named exports, no `any`, no em dashes in prose. Small commits.

## Layout
src/{types,provenance,normalize,recall,ledger,capability,soulguard,firewall,index}.ts, src/detectors/{injection,exfil}.ts, test/, examples/.
