# Carapace x OpenClaw — Integration findings & plan

Read from the live `openclaw-ui-rebuild` checkout on 2026-06-01. Everything below is observed, not assumed. Where something needs confirming against a build, it says so.

## 1. Repo state (the "needs fixing")

**Stale git lock.** `.git/index.lock` (0 bytes, dated Apr 2) is left over from a git process that crashed. It jams the index: 11,376 files report as staged deletions even though all are present on disk, and git cannot commit or pull. This is the broken state.

Fix (run on your machine; the sandbox mount denies deleting the lock):

```bash
cd ~/openclaw-workspace/projects/openclaw-ui-rebuild
rm -f .git/index.lock && git reset && git status   # working tree should go clean
```

PowerShell equivalent: `del .git\index.lock; git reset; git status`

**Version.** Local is `openclaw@2026.4.2-beta.1` (about two months behind). After unlocking: `git pull && pnpm install`. Skim the CHANGELOG for any memory or plugin-SDK changes before wiring.

## 2. How OpenClaw is actually built (confirmed from source)

- pnpm monorepo. `extensions/*` are plugins defined with `definePluginEntry({ id, name, description, kind, register(api) })` from `openclaw/plugin-sdk/plugin-entry`.
- Memory is a plugin `kind`. `memory-core` registers a memory runtime (`api.registerMemoryRuntime`), a flush plan (`api.registerMemoryFlushPlan`), a prompt section, embedding providers, and the `memory_search` / `memory_get` tools (`api.registerTool`).
- **Durable-memory promotion is the flush plan.** Near compaction (~4000 tokens) the agent is prompted to write durable notes to `memory/YYYY-MM-DD.md`, and is *instructed* to treat `MEMORY.md`, `SOUL.md`, `AGENTS.md`, `TOOLS.md` as read-only. That protection is prompt-enforced today. This is precisely the gap Carapace closes.
- There is an in-core before/after tool-call mechanism in the agent runner (`beforeToolCallRuntime` and after-tool-call handlers).

## 3. Where Carapace binds (the real map)

| Carapace plane | OpenClaw surface | Status |
|----------------|------------------|--------|
| Audit tool (`carapace` status/verify/review) | `api.registerTool` | fully wireable now (confirmed pattern) |
| Recall (trust filter) | wrap the memory runtime / `memory_search` tool | confirmed surface |
| Soul integrity | intercept writes to protected files via before-tool-call; replace the prompt-based read-only rule with capability-token enforcement | surface exists; confirm plugin-facing hook |
| Egress (exfil block) | before-tool-call on outbound tools (message send, git push, web post) | surface exists; confirm plugin-facing hook |
| Ingress (tag/quarantine) | after-tool-call on tool results | surface exists; confirm plugin-facing hook |
| Promotion gate | harden the flush plan + intercept writes into `memory/`; full provenance-gated promotion needs session-wide provenance tracking | partial now, deeper later |

## 4. The one thing to confirm

Whether the before/after tool-call hook is exposed to third-party plugins through the plugin `api`, or is core-only. If core-only, wiring the ingress/egress/soul guards needs a small core patch to surface a plugin hook. That is part of "OpenClaw needs an update," and it is confirmable by reading the built `dist/plugin-sdk` types after a `pnpm build`, or the SDK source once the repo is unlocked. The audit tool and recall wrap do not depend on this and can land first.

## 5. Plan, in order

1. You: clear `index.lock` + `git reset` (commands above). Unbreaks the repo.
2. You or me: `git pull && pnpm install && pnpm build` so the plugin-SDK types exist and the adapter can be typechecked against your real build.
3. Me: build `extensions/carapace` as a `definePluginEntry` plugin:
   - registers the `carapace` audit tool (verified pattern),
   - wraps memory recall for trust filtering,
   - enforces protected-file integrity with capability tokens (deterministic, replacing the prompt-only read-only rule),
   - adds the egress exfil guard, on the tool-call hook (or the minimal core patch if the hook is not plugin-facing).
4. Me: a live demo on your real agent. Fire an injection, show Carapace block the protected-file edit and the bad memory write, with the ledger entry. That is the influencer proof.

## 6. Why this is the honest sequence

I will not ship an OpenClaw-coupled adapter I cannot compile against your build. Once the repo is unlocked and built, the adapter is written and verified the same way the Carapace core was: typecheck plus a real run. Until then, this plan is the artifact, and every claim here was read from your actual repository.
