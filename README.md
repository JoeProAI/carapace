# Carapace

**The shell around your agent's brain.** A deterministic memory-integrity firewall for memory-first agents.

LlamaFirewall protects the session. Carapace protects the memory. It sits between everything an agent reads and the permanent memory it trusts, and it refuses to let untrusted input become durable belief without earning it.

See [`SPEC.md`](./SPEC.md) for the full design, threat model, and roadmap.

## Why

OpenClaw treats the LLM as disposable and the memory stack as the real intelligence. That makes memory the crown jewel and the softest target. Today it is protected by a prompt: SOUL.md asks the model to refuse edits to protected files unless it sees the code word "KaKaw." That holds until a model decides not to follow it, which is the definition of prompt injection. Meanwhile the DREAMING pipeline auto-promotes web, wearable, and group-chat content into permanent memory with no provenance or trust checks. Carapace is the tollbooth on that road.

Grounded in the memory-poisoning literature: arXiv:2601.05504 measures the MINJA attack at 95% injection success and proposes the exact two defenses Carapace implements (composite trust scoring and trust-aware memory sanitization).

## Five planes plus a ledger

1. **Ingress** tags provenance, scores trust across orthogonal detectors, quarantines hostile input.
2. **Recall** trust-aware retrieval with temporal decay and pattern filtering. Quarantine never surfaces.
3. **Promotion** the gate on durable-memory writes. Trust floor, no injection flag, corroboration for mid-trust, identity bounds.
4. **Soul** cryptographic protected-file integrity. Ed25519 capability tokens replace the prompt-based code word.
5. **Egress** secret-exfil scan plus alignment check on consequential actions.

Every decision lands in an append-only, hash-chained ledger.

## See it run

![Carapace computing trust verdicts, capability checks, and a hash-chained ledger at runtime](docs/carapace-demo.gif)

```bash
npm install
npm run demo
```

Real output. Every verdict, signature, and hash below is computed at runtime, not hardcoded:

```
1. A stranger in a group chat tries to plant a false memory
  ingress trust: T4   quarantined: false
  injection signal: 0  []
  exfil signal:     0.6  [references-secret-file:.env]
  then tries to become permanent memory:
     -> REJECT  [below-promotion-floor:T4<T2]
  takeaway: blocked by provenance (T4 below the promotion floor), not by keyword matching. trust, not repetition.

2. A real fact from a first-party tool
  ingress trust: T1   quarantined: false
     -> ALLOW  [passed-promotion-gate]

3. An injected instruction tries to rewrite SOUL.md
  write SOUL.md with NO capability token:
     -> REJECT  [no-capability-token, protected-file]

4. Joe authorizes a real SOUL.md change with a signed capability
  write SOUL.md WITH a valid token:
     -> ALLOW  [valid-capability, nonce:kakaw-...]

5. The agent is told to send a secret out
  outbound message carrying a key:
     -> REJECT  [outbound-contains-secrets, openai-stripe-style-key]

6. The audit ledger (real sha256 chain)
  # 0 ingress              allow       c81d587f04598dba...
  # 1 promotion-rejected   reject      62220fd06a538e30...
  # 2 ingress              allow       e9ed65bf782e0f36...
  # 3 promotion            allow       2ea1a2b2974471f9...
  # 4 soul-write-rejected  reject      34998947fd629cea...
  # 5 soul-write           allow       238462cc0b8dd550...
  # 6 egress-blocked       reject      5381604c3df71f8f...

  ledger.verify() -> {"valid":true}
```

## Adversarial results (measured)

`npm run redteam` fires obfuscated attacks from an untrusted web channel and prints real verdicts:

```
  attack                          detected   reached durable memory
  --------------------------------------------------------------
  direct override                yes        no
  zero-width split               yes        no
  spaced out                     yes        no
  homoglyph (cyrillic)           yes        no
  base64 payload                 yes        no
  paraphrase (no keywords)       no         no
  multilingual (es)              no         no
  benign control                 no         no

  fast-layer detection on malicious inputs:      5/7
  malicious inputs that reached durable memory:  0/7
```

Read it straight: normalization defeats the obfuscation bypasses (zero-width, spacing, homoglyph, base64). The fast layer still misses paraphrase and some languages, and that is stated, not hidden. The provenance gate is the backstop: untrusted content never becomes durable memory even when detection misses it. Trust over keywords. The model detector seam is where semantic paraphrase detection plugs in next.

## Quickstart (integration)

```ts
import { createCarapace, DEFAULT_CONFIG, type CarapaceConfig } from "@openclaw/carapace";

const config: CarapaceConfig = {
  ...DEFAULT_CONFIG,
  authorityPublicKeyPem: process.env.CARAPACE_AUTHORITY_PUBKEY ?? "",
};

const cp = createCarapace(config, {
  protectedFiles: [{ path: "SOUL.md", content: soulContents }],
  secretRegistry: [".env", ".firebase-sa.json", "arweave-platform-wallet.json"],
});

// Wrap inbound content before it touches context.
const env = cp.onIngress({ content: webPage, provenance: { source: "crawl4ai:example.com", channel: "web", capturedAt: new Date().toISOString() } });

// Gate the DREAMING promotion path.
if (cp.onMemoryWrite({ envelope: env, target: "MEMORY.md" }).verdict !== "allow") skip(env);
```

## OpenClaw wiring contract

`createCarapace` returns typed handlers. A thin adapter binds them to gateway hooks, the same pattern the `lobster` plugin uses:

| Handler | Hook | Effect |
|---------|------|--------|
| `onIngress` | tool results, web fetch, channel messages, wearable | wrap + score + quarantine |
| `onRecall` | `memory.search` / ChromaDB query | filter by trust, decay, patterns |
| `onMemoryWrite` | DREAMING promotion (`memory.write`) | gate durable writes |
| `onFileWrite` | `file.write` on protected paths | require signed capability |
| `onMessageSend` | `message.send`, `git push`, `tool.invoke` | block exfil, check alignment |

The `carapace` agent tool exposes `status`, `verify`, `review`, and `attest`.

## Capability tokens

The agent holds only the Ed25519 public key. Tokens are minted on a separate authenticated signer (`mintCapability`), so the agent can verify a grant but never forge one. "KaKaw" becomes the human trigger that mints a token through that authenticated path, not a string the model scans for in chat.

## What's real today, and what's next

No fake benchmarks live in this repo. The honest maturity line:

**Real and tested now** (33 passing tests via `npm test`, runnable via `npm run demo`):
provenance and trust derivation, the promotion gate, trust-aware recall with temporal decay, the hash-chained ledger, and Ed25519 capability tokens. All deterministic. Heuristic injection and exfil detectors are real and honestly limited: they catch obvious patterns, not paraphrase.

**Documented, not yet built** (so you are not misled): the model detector (PromptGuard 2) is a clean seam behind the `Detector` interface, not an implementation here. The composite scorer is ready for it; the model is not wired. Wiring into a live OpenClaw DREAMING pipeline is Phase 1.

**On the numbers:** figures cited in `SPEC.md` (attack-success rates, MINJA) are published results from prior work (LlamaFirewall, arXiv:2601.05504) that motivate Carapace. They are not Carapace's own benchmarks. Carapace has not been independently benchmarked yet; when it is, the numbers and the method to reproduce them will live here.

MIT. Built by JoeProAI.
