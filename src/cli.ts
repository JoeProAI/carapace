#!/usr/bin/env node
import { runDemo } from "./demo.js";

const args = process.argv.slice(2);
const help = `Carapax: a trust boundary before agent memory writes.

Usage: carapax demo [--json]
       carapax --help

The demo computes three real decisions using synthetic inputs and an in-memory
store. No account, API key, file access, telemetry, or network calls by the demo.
It does not install protection into your agent.

Integrate: https://carapax.moltagent.run/#use
Mem0: https://github.com/JoeProAI/carapace/tree/main/examples/mem0`;

if (args.length === 0 || (args.length === 1 && ["--help", "-h"].includes(args[0]!))) {
  console.log(help);
} else if (args[0] === "demo" && (args.length === 1 || (args.length === 2 && args[1] === "--json"))) {
  const result = runDemo();
  if (args[1] === "--json") {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log("\nCARAPAX / A trust boundary before memory\n");
    console.log("Real decisions. Synthetic inputs. Local in-memory store.\n");
    for (const scenario of result.scenarios) {
      console.log(`${scenario.verdict.toUpperCase().padEnd(6)} [${scenario.trust}] ${scenario.name}`);
      console.log(`       ${scenario.content}`);
      console.log(`       Why: ${scenario.reasons.join(", ")}\n`);
    }
    console.log(`Stored ${result.stored.length}/${result.scenarios.length} candidate memories.`);
    console.log(`Ledger: ${result.ledger.valid ? "verified" : "INVALID"} (${result.ledger.entries} entries).`);
    console.log(`\n${result.limitation}`);
    console.log("\nNext: npm install carapax");
    console.log("Guide: https://carapax.moltagent.run/#use");
  }
  if (!result.ledger.valid) process.exitCode = 1;
} else {
  console.error(`Unknown arguments.\n\n${help}`);
  process.exitCode = 1;
}
