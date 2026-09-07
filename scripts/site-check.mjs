import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { examples } from "../public/examples.js";

const repository = fileURLToPath(new URL("../", import.meta.url));
execFileSync(process.execPath, ["scripts/site-fixtures.mjs", "--check"], {
  cwd: repository,
  stdio: "inherit",
});
const result = execFileSync(
  process.execPath,
  ["--input-type=module", "--eval", examples.core.code],
  { cwd: repository, encoding: "utf8" },
);
assert.equal(
  result.trim(),
  "reject",
  "The copyable quickstart must work in Node and reject untrusted content",
);
const html = readFileSync(
  new URL("../public/index.html", import.meta.url),
  "utf8",
);
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const demoCommand = `npx carapax@${packageJson.version} demo`;
assert.equal((html.match(new RegExp(`data-copy="${demoCommand.replaceAll(".", "\\.")}"`, "g")) ?? []).length, 2);
assert.ok(html.includes(`v${packageJson.version} IS OUT`));
assert.ok(html.includes('<link rel="canonical" href="https://carapax.moltagent.run/" />'));
assert.ok(html.includes('property="og:url" content="https://carapax.moltagent.run/"'));
assert.ok(html.includes('href="https://github.com/JoeProAI/carapace/tree/main/examples/mem0"'));
assert.ok(html.includes('href="https://github.com/JoeProAI/carapace/issues/new?template=integration_help.md"'));
assert.ok(existsSync(new URL("../.github/ISSUE_TEMPLATE/integration_help.md", import.meta.url)));
const demo = JSON.parse(execFileSync(process.execPath, ["dist/cli.js", "demo", "--json"], { cwd: repository, encoding: "utf8" }));
assert.deepEqual(demo.scenarios.map((s) => s.verdict), ["reject", "allow", "reject"]);
assert.equal(demo.stored.length, 1);
assert.equal(demo.ledger.valid, true);
// Execute the exact copyable Mem0 wrapper with only the external client stubbed.
// The SDK's real transport is covered separately by examples/mem0 tests.
const mem0Code = examples.mem0.code.replace("import MemoryClient from 'mem0ai';", `class MemoryClient {
  constructor() {}
  async add() { throw new Error('Rejected web content reached the client'); }
}`);
const mem0Result = execFileSync(process.execPath, ["--input-type=module", "--eval", mem0Code], { cwd: repository, encoding: "utf8" });
assert.equal(mem0Result.trim(), "[]");
for (const match of html.matchAll(/(?:src|href)="(\/[^"#?]+)"/g)) {
  assert.ok(
    existsSync(new URL(`../public${match[1]}`, import.meta.url)),
    `Missing site asset: ${match[1]}`,
  );
}
for (const match of html.matchAll(/href="#([^"]+)"/g)) {
  assert.ok(html.includes(`id="${match[1]}"`), `Missing anchor: ${match[1]}`);
}
console.log(
  "Site check passed: core fixtures, Node and Mem0 snippets, demo CLI, onboarding links, version, canonical URL, assets and anchors verified.",
);
