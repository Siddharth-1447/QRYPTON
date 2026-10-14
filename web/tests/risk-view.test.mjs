import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import ts from "typescript";
import * as inventory from "../src/lib/inventory-view.ts";

const require = createRequire(import.meta.url);
const compiled = ts.transpileModule(readFileSync(new URL("../src/lib/risk-view.ts", import.meta.url), "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const compiledModule = { exports: {} };
new Function("require", "module", "exports", compiled)(id => id === "./inventory-view" ? inventory : require(id), compiledModule, compiledModule.exports);
const { riskView, nextCell } = compiledModule.exports;
const state = patch => ({ ...inventory.VIEW_DEFAULTS, ...patch });
const row = (id, patch = {}) => ({ finding_id: id, application: "Payments", algorithm_name: "RSA-2048", risk_level: "critical", risk_assessment_state: "assessed", remediation_rank: 1, business_criticality: "critical", observations: { exposure: { state: "observed", value: true } }, migration_status: "planned", ...patch });
const rows = [row("sensitive"), row("weak", { application: "Tools", remediation_rank: 2, risk_level: "high", business_criticality: "low", algorithm_name: "MD5", observations: { exposure: { state: "observed", value: false } } }), row("unknown", { remediation_rank: 3, risk_level: "unknown", business_criticality: "unclassified", migration_status: "blocked" })];
const cells = [
  { mosca_urgency: "critical", business_criticality: "critical", finding_count: 1, finding_ids: ["sensitive"] },
  { mosca_urgency: "not_applicable", business_criticality: "low", finding_count: 1, finding_ids: ["weak"] },
  { mosca_urgency: "unknown", business_criticality: "unclassified", finding_count: 1, finding_ids: ["unknown"] },
];

test("matrix cells partition the filtered inventory and intensity ignores finding volume", () => {
  const view = riskView(cells, rows, state({}), null);
  assert.equal(view.valid, true);
  assert.equal(view.cells.reduce((sum, c) => sum + c.finding_count, 0), view.total);
  assert.deepEqual(view.findings.map(r => r.finding_id), ["sensitive", "weak", "unknown"]);
  assert.equal(view.cells[0].highestRisk, 5);
  assert.equal(view.cells[0].topApplication, "Payments");
  assert.equal(riskView([...cells, cells[0]], rows, state({}), null).valid, false);
});
test("cell selection uses persisted IDs, keeps context counts and clears without losing other filters", () => {
  const selection = { urgency: "critical", criticality: "critical" };
  const view = riskView(cells, rows, state(selection), selection);
  assert.deepEqual(view.findings.map(r => r.finding_id), ["sensitive"]);
  assert.equal(view.total, 3);
  assert.equal(riskView(cells, rows, state({ application: "Tools", ...selection }), selection).findings.length, 0);
  assert.equal(riskView(cells, rows, state({ application: "Tools" }), null).total, 1);
});
test("graph urgency selection includes every criticality without relying on optional inventory urgency", () => {
  const graphCells = cells.map(cell => cell.finding_ids.includes("weak") ? { ...cell, mosca_urgency: "critical" } : cell);
  const selection = { urgency: "critical", criticality: "" };
  const view = riskView(graphCells, rows, state(selection), selection);
  assert.equal(view.valid, true);
  assert.equal(view.total, 3);
  assert.deepEqual(view.findings.map(finding => finding.finding_id), ["sensitive", "weak"]);
});
test("all six filters and single-finding selection round-trip in the URL and apply exactly", () => {
  for (const patch of [{ application: "Tools" }, { algorithm: "MD5" }, { criticality: "low" }, { exposure: "no" }, { risk: "high" }, { migration: "planned", finding: "weak" }]) {
    const restored = inventory.readInventoryView(inventory.writeInventoryView("id=run_one", state(patch)));
    assert.deepEqual(restored, state(patch));
    assert.deepEqual(riskView(cells, rows, restored, null).findings.map(r => r.finding_id), ["weak"]);
  }
});
test("keyboard cell navigation wraps predictably and Home/End stay in the row", () => {
  assert.equal(nextCell(4, "ArrowRight"), 0);
  assert.equal(nextCell(0, "ArrowLeft"), 4);
  assert.equal(nextCell(27, "ArrowDown"), 2);
  assert.equal(nextCell(2, "ArrowUp"), 27);
  assert.equal(nextCell(12, "Home"), 10);
  assert.equal(nextCell(12, "End"), 14);
  assert.equal(nextCell(12, "Enter"), 12);
});
