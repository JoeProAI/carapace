import { execFileSync, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const scratch = mkdtempSync(join(tmpdir(), "carapax-package-smoke-"));
const npmExecPath = process.env.npm_execpath;

const runNpm = (args, options) =>
  npmExecPath
    ? execFileSync(process.execPath, [npmExecPath, ...args], options)
    : execFileSync("npm", args, options);

try {
  const packOutput = runNpm(
    ["pack", "--ignore-scripts", "--json", "--pack-destination", scratch],
    { cwd: repositoryRoot, encoding: "utf8" },
  );
  const [packed] = JSON.parse(packOutput);
  if (!packed?.filename || !Array.isArray(packed.files)) {
    throw new Error("npm pack did not return an inspectable package manifest");
  }

  const packagedPaths = new Set(packed.files.map((file) => file.path));
  const requiredPaths = [
    "dist/index.js",
    "dist/index.d.ts",
    "dist/adapters/mem0.js",
    "dist/adapters/mem0.d.ts",
    "dist/cli.js",
    "dist/demo.js",
  ];
  const missing = requiredPaths.filter((path) => !packagedPaths.has(path));
  if (missing.length > 0) {
    throw new Error(`package is missing required files: ${missing.join(", ")}`);
  }

  const consumer = join(scratch, "consumer");
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  runNpm(
    ["install", join(scratch, packed.filename), "--ignore-scripts", "--no-audit", "--no-fund"],
    { cwd: consumer, stdio: "pipe" },
  );

  const check = `
    const core = await import("carapax");
    const mem0 = await import("carapax/adapters/mem0");
    if (typeof core.createCarapace !== "function") throw new Error("createCarapace export is unavailable");
    if (typeof mem0.withCarapace !== "function") throw new Error("withCarapace export is unavailable");
  `;
  execFileSync(process.execPath, ["--input-type=module", "--eval", check], {
    cwd: consumer,
    stdio: "pipe",
  });

  const installed = JSON.parse(readFileSync(join(consumer, "node_modules", "carapax", "package.json"), "utf8"));
  assert.equal(installed.bin.carapax, "./dist/cli.js");
  const cli = join(consumer, "node_modules", "carapax", "dist", "cli.js");
  const result = JSON.parse(execFileSync(process.execPath, [cli, "demo", "--json"], { encoding: "utf8" }));
  assert.deepEqual(result.scenarios.map((s) => s.verdict), ["reject", "allow", "reject"]);
  assert.equal(result.stored.length, 1);
  assert.equal(result.ledger.valid, true);
  assert.match(execFileSync(process.execPath, [cli, "--help"], { encoding: "utf8" }), /Usage: carapax demo/);
  assert.match(execFileSync(process.execPath, [cli, "demo"], { encoding: "utf8" }), /Stored 1\/3/);
  assert.equal(spawnSync(process.execPath, [cli, "typo"], { encoding: "utf8" }).status, 1);
  // Exercise npm's generated executable shim, not just the underlying JS file.
  const shim = runNpm(["exec", "--offline", "--", "carapax", "demo", "--json"], { cwd: consumer, encoding: "utf8" });
  assert.equal(JSON.parse(shim).stored.length, 1);
  console.log(`package smoke passed: carapax@${installed.version}, public imports and installed CLI verified`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
