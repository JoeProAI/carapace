import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { protectMemory, runScenarios, preference } from "./boundary.mjs";

test("real mem0ai SDK only sends the allowed memory; transport is mocked", async () => {
  process.env.MEM0_TELEMETRY = "false";
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (input, options = {}) => {
    const url = new URL(String(input));
    assert.equal(url.origin, "https://mem0.test.invalid", "No real service may be contacted");
    if (url.pathname === "/v1/ping/" && options.method === "GET") {
      return Response.json({ status: "ok" });
    }
    assert.equal(options.method, "POST");
    assert.equal(url.pathname, "/v3/memories/add/");
    requests.push(JSON.parse(options.body));
    return Response.json({ results: [{ id: "synthetic-id", event: "ADD" }] });
  };
  try {
    const { default: MemoryClient } = await import("mem0ai");
    const decisions = [];
    const memory = protectMemory(new MemoryClient({ apiKey: "synthetic-test-key", host: "https://mem0.test.invalid" }),
      ({ decision }) => decisions.push(decision));
    await runScenarios(memory, "test-user");
    assert.deepEqual(decisions.map((d) => d.verdict), ["reject", "allow", "reject"]);
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].messages, [{ role: "user", content: preference }]);
    assert.equal(requests[0].user_id, "test-user");
    assert.ok(!Object.keys(requests[0]).some((key) => key.startsWith("carapace")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("unlabeled inputs fail closed regardless of role", async () => {
  const memory = protectMemory({ async add() { assert.fail("Unlabeled input reached the store"); } });
  for (const role of ["user", "assistant"]) {
    assert.deepEqual(await memory.add([{ role, content: preference }], { userId: "test-user" }), []);
  }
});

test("gate rejection is distinct from a store error", async () => {
  const memory = protectMemory({ async add() { throw new Error("synthetic store outage"); } });
  await assert.rejects(() => runScenarios(memory, "test-user"), /synthetic store outage/);
});

test("hosted example refuses to run without opt-in or credentials", () => {
  const env = { ...process.env };
  delete env.MEM0_API_KEY;
  for (const args of [[], ["--live"]]) {
    const result = spawnSync(process.execPath, ["hosted.mjs", ...args], {
      cwd: new URL(".", import.meta.url), env, encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Opt-in required|Set MEM0_API_KEY/);
  }
});
