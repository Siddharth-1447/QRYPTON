import assert from "node:assert/strict";
import { test } from "node:test";
import { observed, timelineGeometry, safeMetadata, applicationHref } from "../src/lib/finding-investigation.ts";

const timeline = { mosca_applicable: "yes", x_data_lifetime_years: 7, y_migration_years: 3, z_crqc_horizon_years: 8, required_security_years: 10, time_margin_years: -2 };
test("timeline renders overflow without substituting a risk calculation", () => {
  const g = timelineGeometry(timeline);
  assert.ok(g.overflow > 0);
  assert.ok(Math.abs(g.x + g.y - g.z - g.overflow) < 1e-10);
  assert.equal(timelineGeometry({ ...timeline, time_margin_years: 0 }).overflow, 0);
  assert.equal(timelineGeometry({ ...timeline, time_margin_years: 2 }).overflow, 0);
  assert.equal(timelineGeometry({ ...timeline, mosca_applicable: "no" }), null);
  assert.equal(timelineGeometry({ ...timeline, x_data_lifetime_years: null }), null);
  assert.equal(timelineGeometry({ ...timeline, z_crqc_horizon_years: Infinity }), null);
  assert.ok(timelineGeometry({ ...timeline, x_data_lifetime_years: 0, y_migration_years: 0, z_crqc_horizon_years: 0, required_security_years: 0, time_margin_years: 0 }));
});
test("recorded values preserve precision, false and zero; missing observations stay unknown", () => {
  for (const value of [0, false, 73.125, "restricted"]) assert.equal(observed({ state: "observed", value }), String(value));
  assert.equal(observed({ state: "unknown", value: 99 }), "Unknown");
  assert.equal(observed(), "Unknown");
});
test("sensitive metadata is withheld and application links stay local", () => {
  for (const value of ["password=abc", "-----BEGIN PRIVATE KEY-----", "a".repeat(64), "api_key: abc"]) assert.equal(safeMetadata(value), "[Sensitive metadata withheld]");
  assert.equal(safeMetadata("src/crypto.py"), "src/crypto.py");
  const link = new URL(applicationHref("run/one", "Payments & cards"), "https://localhost");
  assert.equal(link.origin, "https://localhost");
  assert.equal(link.searchParams.get("iv.q"), "Payments & cards");
});
