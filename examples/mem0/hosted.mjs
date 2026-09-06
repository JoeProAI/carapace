import { randomUUID } from "node:crypto";
import { protectMemory, runScenarios } from "./boundary.mjs";

// Do not construct the SDK client or read an API key without explicit opt-in.
if (process.argv.length !== 3 || process.argv[2] !== "--live") {
  console.error("Opt-in required: npm run live. This sends synthetic allowed content to Mem0 and may incur charges. Use npm start for the free local demo.");
  process.exitCode = 1;
} else if (!process.env.MEM0_API_KEY) {
  console.error("Set MEM0_API_KEY privately in your shell before opting in. Never commit it.");
  process.exitCode = 1;
} else {
  process.env.MEM0_TELEMETRY = "false";
  const { default: MemoryClient } = await import("mem0ai");
  const userId = `carapax-demo-${randomUUID()}`;
  console.log(`Opted into a real Mem0 add request. Demo user_id: ${userId}`);
  console.log("The allowed synthetic preference will be sent to Mem0. No existing memories are deleted.");
  const memory = protectMemory(new MemoryClient({ apiKey: process.env.MEM0_API_KEY }), ({ decision }) => {
    console.log(`${decision.verdict.toUpperCase()} [${decision.trust}] ${decision.reasons.join(", ")}`);
  });
  try {
    await runScenarios(memory, userId);
    console.log("Allowed add request completed. Verify processing in your Mem0 dashboard; an accepted request does not prove persistence.");
    console.log(`Remove this demo user's data through your normal Mem0 workflow when finished: ${userId}`);
  } catch {
    console.error("Mem0 request failed. Check account access and service status. Check the demo user before retrying; a network error may follow a successful write.");
    process.exitCode = 1;
  }
}
