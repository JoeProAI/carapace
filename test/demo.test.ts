import { describe, it, expect } from "vitest";
import { runDemo } from "../src/demo.js";

describe("adoption demo", () => {
  it("persists only the trusted preference and verifies the ledger", () => {
    const result = runDemo();
    expect(result.scenarios.map((s) => s.verdict)).toEqual(["reject", "allow", "reject"]);
    expect(result.scenarios.map((s) => s.trust)).toEqual(["T4", "T0", "T4"]);
    expect(result.scenarios[0]?.quarantined).toBe(true);
    expect(result.scenarios[2]?.quarantined).toBe(false);
    expect(result.scenarios[2]?.reasons).toContain("below-promotion-floor:T4<T2");
    expect(result.stored).toEqual([result.scenarios[1]?.content]);
    expect(result.ledger.valid).toBe(true);
    expect(result.ledger.entries).toBe(6);
  });

  it("starts with a fresh store each run", () => {
    const first = runDemo();
    first.stored.push("not part of the next run");
    expect(runDemo().stored).toHaveLength(1);
  });
});
