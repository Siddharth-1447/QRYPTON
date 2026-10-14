import assert from "node:assert/strict";
import { test } from "node:test";
import { sectionAtScrollPosition } from "../src/lib/section-navigation.ts";

test("landing and sections that have not mounted default to Dashboard", () => {
  assert.equal(sectionAtScrollPosition([]), "dashboard");
  assert.equal(sectionAtScrollPosition([{ id: "results-section", top: 500 }]), "dashboard");
});
test("scroll tracking follows document positions even when nav order differs", () => {
  assert.equal(sectionAtScrollPosition([
    { id: "inventory", top: -400 }, { id: "dashboard", top: -1000 },
    { id: "risk", top: 100 }, { id: "reports", top: 700 },
  ]), "risk");
});
test("scrolling upward restores the preceding section until the next heading crosses the line", () => {
  assert.equal(sectionAtScrollPosition([{ id: "inventory", top: -300 }, { id: "risk", top: 121 }]), "inventory");
});
test("bottom of document activates the final section even if too short to reach the line", () => {
  assert.equal(sectionAtScrollPosition([{ id: "your-scans", top: 260 }, { id: "reports", top: -500 }], 120, true), "your-scans");
});
