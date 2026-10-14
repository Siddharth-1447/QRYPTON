import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { test } from "node:test";
import { buildInventoryRows, filterInventory, inventoryCsv, readInventoryView, writeInventoryView, VIEW_DEFAULTS, PRESET_VIEWS, virtualWindow, INVENTORY_ROW_HEIGHT } from "../src/lib/inventory-view.ts";

const fixture = (id, overrides = {}) => ({
  finding_id: `finding_${id}`, category: "algorithm_use", algorithm_name: "RSA", algorithm_family: "asymmetric_encryption",
  algorithm_variant: null, crypto_role: "encryption", library_name: "openssl", identity_status: "identified", identity_label: "RSA", identification_confidence: .9, usage_confidence: .8, confidence_reasons: [], key_size_bits: 2048, lifecycle_status: "legacy", risk_level: "high", risk_assessment_state: "assessed", business_criticality: "high", risk_score: 75, confidence: .9, evidence_count: 1, first_observed_at: "2026-10-09", last_observed_at: "2026-10-09", application: "Payments", asset_id: "asset_payments", artifact_type: "source_repo", source_surfaces: ["source"], environment: "production", quantum_status: "vulnerable", timeline_overflow: true, mosca_urgency: "high", missing_business_context: false, migration_status: "untriaged", observations: { exposure: { state: "observed", value: true }, data_lifetime: { state: "observed", value: 7 } }, evidence_rows: [{ id: `evidence_${id}`, location: "src/payments.py · line 4", kind: "source_ast", surface: "source", confidence: .9 }], ...overrides,
});
const state = (overrides = {}) => ({ ...VIEW_DEFAULTS, expanded: [], ...overrides });

test("all filters, sort, layout and expanded groups survive a shared URL", () => {
  const original = state({ q: "RSA + payments", risk: "critical,high", family: "asymmetric_encryption", quantum: "vulnerable", surface: "source", criticality: "high", environment: "production", exposure: "yes", confidence: "high", migration: "planned", urgency: "high", context: "missing", timeline: "overflow", view: "raw", sort: "confidence", direction: "asc", expanded: ["a:one", "f:one", "a:one"] });
  const url = writeInventoryView("id=run_one&unrelated=keep", original);
  assert.equal(new URLSearchParams(url).get("id"), "run_one");
  assert.equal(new URLSearchParams(url).get("unrelated"), "keep");
  assert.deepEqual(readInventoryView(url), { ...original, expanded: ["a:one", "f:one"] });
  assert.deepEqual(readInventoryView(writeInventoryView(url, state())), state());
  assert.equal(readInventoryView("iv.sort=madeup&iv.view=madeup&iv.direction=madeup").sort, "risk_level");
});

test("default application groups aggregate counts and known risk without suppressing uncertainty", () => {
  const items = [fixture("one"), fixture("two", { risk_level: "critical" }), fixture("three", { risk_level: "unknown", risk_assessment_state: "unassessed" })];
  const grouped = buildInventoryRows(items, state());
  assert.equal(grouped.length, 1);
  assert.equal(grouped[0].items.length, 3);
  assert.equal(grouped[0].highest, "critical");
  assert.equal(grouped[0].uncertain, 1);
  assert.equal(grouped[0].evidenceCount, 3);
  const applications = buildInventoryRows(items, state({ expanded: [grouped[0].key] }));
  const algorithm = applications[1];
  assert.equal(algorithm.kind, "algorithm");
  const findings = buildInventoryRows(items, state({ expanded: [grouped[0].key, algorithm.key, "f:finding_one"] }));
  assert.equal(findings.filter((r) => r.kind === "finding").length, 3);
  assert.equal(findings.filter((r) => r.kind === "evidence").length, 1);
  assert.equal(buildInventoryRows(items, state({ view: "raw" })).length, 3);
});

test("unknown application and algorithm identities never collapse unrelated findings", () => {
  const items = [fixture("one", { asset_id: null, application: null, algorithm_name: null }), fixture("two", { asset_id: null, application: null, algorithm_name: null })];
  assert.equal(buildInventoryRows(items, state()).length, 2);
});

test("all investigation filters intersect and search evidence locations and owners", () => {
  const match = fixture("one", { assigned_owner: "Crypto team", migration_status: "planned" });
  const miss = fixture("two", { environment: "development", observations: { exposure: { state: "unknown", value: null } } });
  const filters = { risk: "high", family: "asymmetric_encryption", quantum: "vulnerable", surface: "source", criticality: "high", environment: "production", exposure: "yes", confidence: "high", migration: "planned", urgency: "high", timeline: "overflow" };
  assert.deepEqual(filterInventory([match, miss], state(filters)).map((r) => r.finding_id), [match.finding_id]);
  assert.equal(filterInventory([match], state({ q: "src/payments.py" })).length, 1);
  assert.equal(filterInventory([match], state({ q: "Crypto team" })).length, 1);
  for (const [filter, value] of Object.entries({ risk: "critical", family: "hash", quantum: "resistant", surface: "kms", criticality: "low", environment: "staging", exposure: "no", confidence: "low", migration: "blocked", urgency: "low" })) assert.equal(filterInventory([match], state({ [filter]: value })).length, 0, filter);
});

test("presets exclude resolved findings and never infer exposure or Mosca overflow", () => {
  const rows = [fixture("one"), fixture("two", { migration_status: "migrated" }), fixture("three", { timeline_overflow: null, observations: { exposure: { state: "unknown", value: null } }, missing_business_context: true })];
  assert.equal(filterInventory(rows, state(PRESET_VIEWS["Fix this sprint"])).length, 2);
  assert.equal(filterInventory(rows, state(PRESET_VIEWS["Internet-facing and X+Y>Z"])).length, 2);
  assert.deepEqual(filterInventory(rows, state(PRESET_VIEWS["Missing business context"])).map((r) => r.finding_id), [rows[2].finding_id]);
  assert.equal(filterInventory(rows, state({ exposure: "no" })).length, 0);
  assert.equal(filterInventory(rows, state({ exposure: "unknown" })).length, 1);
});

test("sorts are deterministic, and unavailable risk scores remain last", () => {
  const rows = [fixture("c", { risk_score: null }), fixture("b", { risk_score: 90 }), fixture("a", { risk_score: 20 })];
  assert.deepEqual(filterInventory(rows, state({ sort: "risk_score", direction: "asc" })).map((r) => r.finding_id), ["finding_a", "finding_b", "finding_c"]);
  assert.deepEqual(filterInventory(rows, state({ sort: "risk_score", direction: "desc" })).map((r) => r.finding_id), ["finding_b", "finding_a", "finding_c"]);
});

test("1,500 findings plus evidence stay bounded to the visible window", () => {
  const rows = Array.from({ length: 1500 }, (_, index) => fixture(String(index)));
  const started = performance.now();
  const filtered = filterInventory(rows, state({ view: "raw", q: "payments" }));
  const display = buildInventoryRows(filtered, state({ view: "raw", expanded: rows.map((r) => `f:${r.finding_id}`) }));
  assert.equal(display.length, 3000);
  for (const scroll of [0, 50000, 250000]) {
    const window = virtualWindow(display.length, scroll, 560);
    assert.ok(window.end - window.start <= 16);
    assert.equal(window.before + (window.end - window.start) * INVENTORY_ROW_HEIGHT + window.after, display.length * INVENTORY_ROW_HEIGHT);
  }
  assert.ok(performance.now() - started < 1000, "large inventory projection should complete within one second even on CI");
});

test("CSV preserves original columns, exports every filtered row and neutralizes spreadsheet formulas", () => {
  const rows = Array.from({ length: 1200 }, (_, index) => fixture(String(index), { application: '=HYPERLINK("https://bad.test")' }));
  const csv = inventoryCsv(rows, true);
  assert.equal(csv.split("\n").length, 1201);
  for (const name of ["finding_id", "algorithm_identity", "identity_status", "family", "variant", "crypto_role", "library", "category", "risk_score", "final_risk_tier", "assessment_state", "business_criticality", "lifecycle_status", "evidence_count", "confidence", "assigned_owner", "migration_status"]) assert.ok(csv.split("\n")[0].split(",").includes(name));
  assert.match(csv, /"'=HYPERLINK/);
  assert.match(csv, /Sample data/);
});
