# Put a trust boundary before Mem0 adds

A runnable JavaScript example using Carapax's real local gate. Rejected messages never reach the wrapped client's `add` method. This is a community example, not a Mem0-endorsed integration.

## Try it locally in five minutes

Requires Node.js 22+ and npm. Installation downloads dependencies; the local demo itself makes no network requests, reads no personal files, and needs no key or account.

```sh
git clone https://github.com/JoeProAI/carapace.git
cd carapace/examples/mem0
npm ci --ignore-scripts
npm start
npm test
```

Expected decisions:

| Synthetic candidate | Source | Verdict |
| --- | --- | --- |
| Instruction to exfiltrate secrets | Untrusted web, T4 | Reject |
| Preference for concise answers and metric units | Authenticated principal, T0 | Allow |
| Exactly the same preference | Untrusted web, T4 | Reject |

The console ends with `PASS: 1 of 3 candidate memories reached the local store.` The store is an in-memory stand-in, not a live Mem0 backend. Every decision comes from Carapax, not a canned response.

## Wire it into your application

Copy `boundary.mjs` into your Node application. Its `protectMemory` helper wraps a client and rejects unlabeled inputs by default. `runScenarios` contains synthetic labels for demonstration only; do not use it as application authentication code.

```js
import MemoryClient from "mem0ai";
import { protectMemory } from "./boundary.mjs";

const memory = protectMemory(new MemoryClient({ apiKey: process.env.MEM0_API_KEY }));

// These are external web contents, regardless of their message role.
const result = await memory.add([
  { role: "user", content: "The user prefers concise answers." },
], {
  userId: "your-application-user",
  carapaceProvenance: {
    source: "web:example.com", channel: "web", authenticated: false,
  },
});
console.log(result); // []: no message passed the gate; Mem0.add was not called.
```

Only trusted server-side code should assign `direct` and `authenticated: true`, after checking that the source has authority to write this user's memory. A logged-in stranger is not automatically a trusted principal. Preserve original provenance through tools and agent summaries; do not upgrade web content merely because an assistant repeated it.

Mem0 SDK 3.x uses `userId` in JavaScript and serializes it as `user_id` on the wire. This example pins `mem0ai@3.1.8` and the already-published `carapax@0.1.1` adapter. It does not require the new demo CLI release.

## Optional real Mem0 run

`hosted.mjs` refuses to create a client without `--live` and `MEM0_API_KEY`. Set the key privately in your shell, then run:

```sh
npm run live
```

This opts into Mem0 API traffic and any associated charges. It sends the one allowed synthetic preference under a new `carapax-demo-<uuid>` user. SDK telemetry is disabled before import. No real API calls were made during automated verification. A successful add response is not proof of finished memory extraction or persistence. Check the dashboard, then remove that demo user's data through your normal Mem0 workflow. The example does not delete anything automatically.

## What is verified

- Local demo asserts that only the trusted preference reaches its store.
- Tests run the actual pinned Mem0 SDK with a mocked HTTP transport: exactly one memory-add request, correct `user_id`, and no Carapax-only options leaked into the request.
- Unlabeled user and assistant messages are rejected.
- Store errors propagate; they are not reported as gate rejections.
- Hosted execution requires explicit opt-in and credentials.

The API backend, authentication, extraction quality, OSS `Memory` class, and other SDK versions are not covered by this check. The SDK install includes its own dependencies; Carapax's core still has zero runtime dependencies.

## Scope and troubleshooting

- **Only `add` is gated.** `update`, search, reads, deletion, and calls on an unwrapped client pass through or bypass this boundary. Route every memory mutation through an appropriate policy; this wrapper alone does not secure the entire store.
- **Rejected benign web text is intentional.** A trust-floor rejection does not mean the detector found an attack. Keep it as untrusted context, or design an explicit review/corroboration policy. Do not relabel it as trusted to silence a rejection.
- **An empty array means no survivors**, not an API outage. Use `onDecision` for reasons; avoid logging private message content by default.
- **One provenance override applies to the entire add call.** Split differently sourced inputs into separate calls before gating.
- **Do not trust client-supplied labels.** Carapax enforces supplied provenance; it cannot authenticate the source for you. Heuristic detection can miss attacks.

Need help? [Open an integration question](https://github.com/JoeProAI/carapace/issues/new/choose) with SDK/Node versions, sanitized code, expected verdict, and actual reasons. Never include API keys or private memories. Use [private security reporting](https://github.com/JoeProAI/carapace/security/advisories/new) for vulnerabilities.
