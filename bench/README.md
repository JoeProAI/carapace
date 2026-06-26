# Carapax benchmark harness

A reproducible harness that measures the three numbers a security buyer asks
about. It runs the real firewall over a labelled corpus and prints only values
produced at runtime. Nothing is hardcoded; change the corpus and the numbers
change.

```
npm run bench
```

## What it measures

### 1. Efficacy: do memory-injection attacks reach durable memory?

The threat model is MINJA: an attacker plants records in the agent's memory bank
so a payload is recalled and acted on later. The corpus is a set of
**MINJA-style** reproductions of that pattern, grouped by evasion family (plain,
obfuscation, paraphrase, multilingual, indirect, identity, extraction, and
subtle "bridging" records). These are hand-written reproductions, **not the
paper's exact dataset**.

For each attack we compare three defenses:

- **undefended**: a store-everything agent. Every injected record persists.
- **naive keyword filter**: blocks a few literal phrases, no normalization.
  Representative of a quick in-house guard.
- **Carapax**: the real path. `onIngress` (provenance + detectors + ledger)
  then `onMemoryWrite` (the promotion gate).

An attack "reaches durable memory" when the promotion verdict is `allow`.

The reference anchor is MINJA (arXiv:2601.05504), which reports roughly **95%
injection success against undefended memory agents**. The undefended row here is
consistent with that.

### 2. Latency: what does the firewall cost per operation?

Times three paths over many iterations with warmup, using
`process.hrtime.bigint()`, and reports p50 / p95 / p99 / mean in microseconds:

- **baseline store**: hash the content and keep it. No firewall.
- **Carapax ingress**: provenance + detectors + ledger append.
- **Carapax full write**: ingress plus the promotion gate, modelling a real
  accepted write (authenticated first-party input that promotes).

These are **in-process** figures for the deterministic hot path. There is no
model detector (the PromptGuard 2 seam is not wired) and no network. A hosted
Worker adds one HTTP hop on top.

### 3. False positives: is benign content wrongly flagged?

Benign corpus includes **adversarially-hard** items that carry trigger words
("ignore", "system prompt", "update memory", base64-looking ids) in innocent
contexts, so the rate is not measured on trivially clean text. We report:

- detector false-positive rate over all benign items, and over the hard subset;
- **legitimate trusted memory wrongly blocked**: for benign content on
  authenticated first-party channels (T0/T1), how often a flag wrongly prevents
  promotion. This is the real cost of a false positive.

A flagged item is **quarantined, not deleted**: it stays readable as context, it
just is not promoted to durable memory as fact.

## Provenance model

`deriveTrust` only ever lowers trust. First-party channels (the principal's
authenticated `direct` input, the agent's own `filesystem` and `tool` output)
can be trusted (T0/T1); third-party channels (`web`, `api`, `group`, `ambient`,
`subagent`) are not, and an attacker cannot authenticate as the principal. In
the harness, benign first-party content is authenticated and attacks never are,
which is exactly the asymmetry the firewall is designed around.

## Honesty notes (printed by the harness, repeated here)

- Attacks are MINJA-style reproductions, not the exact paper dataset.
- The fast detector is a deterministic heuristic. It misses paraphrase, several
  languages, and subtle bridging records. That is shown, not hidden.
- Carapax's strength here is the **provenance gate, not detection**: untrusted
  content cannot become durable memory even when detection misses it.
- The model-detector seam (PromptGuard 2) is **not wired**. These are the
  heuristic-only floor; a wired classifier would only raise detection recall.
- If an attacker controls a trusted (T0/T1) channel, detection becomes the
  load-bearing layer and its recall is the limit.

## Files

- `corpus.ts`: labelled attacks and benign items (with hard cases).
- `harness.ts`: timing, percentiles, firewall builder, provenance helpers.
- `run.ts`: orchestrates the three measurements and prints the report.
