import assert from "node:assert/strict";
import { protectMemory, runScenarios, preference } from "./boundary.mjs";

const stored = [];
const client = {
  async add(messages, options) {
    stored.push(...messages);
    assert.equal(options.userId, "carapax-local-demo");
    assert.equal(options.carapaceProvenance, undefined);
    return messages.map((_, index) => ({ id: `local-${index}` }));
  },
};
console.log("Carapax + Mem0-shaped LOCAL store. No Mem0 API or model is called.\n");
const memory = protectMemory(client, ({ decision }) => {
  console.log(`${decision.verdict.toUpperCase()} [${decision.trust}] ${decision.reasons.join(", ")}`);
});
await runScenarios(memory, "carapax-local-demo");
assert.deepEqual(stored, [{ role: "user", content: preference }]);
console.log("\nPASS: 1 of 3 candidate memories reached the local store.");
console.log("Source trust is essential: even the benign web preference was rejected.");
