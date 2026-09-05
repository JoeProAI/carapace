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
  "Site check passed: recorded outputs match the core, copyable quickstart executes, local assets and anchors resolve.",
);
