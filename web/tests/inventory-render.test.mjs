import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";
import * as inventory from "../src/lib/inventory-view.ts";
import * as investigation from "../src/lib/finding-investigation.ts";

const require = createRequire(import.meta.url);
const code = ts.transpileModule(readFileSync(new URL("../src/components/crypto-inventory.tsx", import.meta.url), "utf8"), { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } }).outputText;
const compiledModule = { exports: {} };
const primitive = (tag) => function TestPrimitive({ children, variant: ignoredVariant, ...props }) { void ignoredVariant; return React.createElement(tag, props, children); };
const load = (name) => {
  if (name === "@/components/ui/expand-details") {
    const source = ts.transpileModule(readFileSync(new URL("../src/components/ui/expand-details.tsx", import.meta.url), "utf8"), { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } }).outputText;
    const result = { exports: {} };
    new Function("require", "module", "exports", source)(require, result, result.exports);
    return result.exports;
  }
  if (name === "@/components/glossary") return { GlossaryText: ({ children }) => React.createElement("span", null, children) };
  if (name === "@/components/finding-status") return { FindingStatus: () => null };
  if (name === "@/components/finding-ticket") return { FindingTicket: () => null };
  if (name === "@/lib/finding-investigation") return investigation;
  if (name === "@/components/finding-investigation") {
    const source = ts.transpileModule(readFileSync(new URL("../src/components/finding-investigation.tsx", import.meta.url), "utf8"), { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } }).outputText;
    const result = { exports: {} };
    new Function("require", "module", "exports", source)((id) => id === "./ui/primitives" ? load("@/components/ui/primitives") : load(id), result, result.exports);
    return result.exports;
  }
  if (name === "@/lib/api") return { API_BASE: "http://scan.test" };
  if (name === "@/lib/inventory-view") return inventory;
  if (name === "@/components/ui/primitives") return { Button: primitive("button"), Card: primitive("section"), CardHeader: primitive("header"), CardContent: primitive("div"), CardTitle: primitive("h2"), Input: primitive("input"), RiskBadge: ({ level }) => React.createElement("span", null, level) };
  return require(name);
};
new Function("require", "module", "exports", code)(load, compiledModule, compiledModule.exports);
const { CryptoInventory, KnowledgeValue } = compiledModule.exports;
const renderValue = (observation) => renderToStaticMarkup(React.createElement(KnowledgeValue, { observation }));

test("Unknown, Not observed and evidence-backed Confirmed absent have distinct styles and explanations", () => {
  for (const [state, label] of [["unknown", "Unknown"], ["not_observed", "Not observed"], ["confirmed_absent", "Confirmed absent"]]) {
    const html = renderValue({ state, value: null, evidence_ids: state === "confirmed_absent" ? ["evidence_proof"] : [] });
    assert.ok(html.includes(`data-knowledge="${state}"`));
    assert.ok(html.includes(label));
    assert.ok(html.includes("title="));
    assert.ok(html.includes('tabindex="0"'));
  }
  assert.match(renderValue({ state: "confirmed_absent", value: null, evidence_ids: [] }), /data-knowledge="unknown"/);
  assert.match(renderValue({ state: "observed", value: 0 }), />0<\/span>/);
  assert.match(renderValue({ state: "observed", value: false }), />false<\/span>/);
});

test("a 1,200-row raw inventory renders bounded DOM while preserving every column and export", () => {
  const row = { finding_id: "finding_one", category: "algorithm_use", algorithm_name: "RSA", algorithm_family: "asymmetric_encryption", algorithm_variant: null, crypto_role: "encryption", library_name: null, identity_status: "identified", identity_label: "RSA", identification_confidence: .9, usage_confidence: .8, confidence_reasons: [], key_size_bits: 2048, lifecycle_status: "legacy", risk_level: "high", risk_assessment_state: "assessed", business_criticality: "unclassified", risk_score: 75, confidence: .9, evidence_count: 1, first_observed_at: "2026-10-09", last_observed_at: "2026-10-09", application: "Payments", asset_id: "asset_payments" };
  const items = Array.from({ length: 1200 }, (_, index) => ({ ...row, finding_id: `finding_${index}` }));
  const html = renderToStaticMarkup(React.createElement(CryptoInventory, { items, state: { ...inventory.VIEW_DEFAULTS, view: "raw" }, onViewChange: () => {}, onSelect: () => {}, runId: "run_test", onActionsComplete: async () => {} }));
  assert.match(html, /aria-rowcount="1201"/);
  assert.ok((html.match(/class="inventory-data-row/g) ?? []).length <= 16);
  for (const label of ["Finding ID / category", "Algorithm / identity", "Family / status", "Function", "Key size / mode", "Artifact type", "Location / evidence / last observed", "Application", "Exposure", "Business criticality", "Data lifetime", "Quantum status", "Risk score / tier", "Confidence", "Migration status / owner", "Algorithm lifecycle", "Detail", "Export CSV"]) assert.ok(html.includes(label), label);
});

test("drawer motion is 200ms and reduced-motion users get static changes", () => {
  const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
  assert.match(css, /finding-slide-in 200ms/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ \.finding-slide-over \{ animation: none;/);
});

test("standalone finding detail preserves observation distinctions and requires absence evidence", () => {
  const detailCode = ts.transpileModule(readFileSync(new URL("../src/components/finding-detail.tsx", import.meta.url), "utf8"), { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } }).outputText;
  const detailModule = { exports: {} };
  const detailLoad = (name) => name === "@/components/ui/primitives" ? { ...load(name), Badge: primitive("span"), Alert: primitive("div") } : load(name);
  new Function("require", "module", "exports", detailCode)(detailLoad, detailModule, detailModule.exports);
  const detail = { finding: { id: "finding_test", category: "algorithm_use", confidence: .9, first_observed_at: "2026-10-09", last_observed_at: "2026-10-09" }, business_criticality: "unclassified", evidence_provenance: [{ id: "evidence_proof", kind: "source_ast", confidence: .9 }], recommendations: [], assessment: { level: "unknown", factors: { cryptographic_obsolescence: { state: "unknown" }, quantum_exposure: { state: "not_observed" }, exploitability: { state: "confirmed_absent", basis_evidence_ids: ["evidence_proof"] }, business_impact: { state: "confirmed_absent", basis_evidence_ids: ["evidence_missing"] } } } };
  const html = renderToStaticMarkup(React.createElement(detailModule.exports.FindingDetail, { open: true, fullPage: true, loading: false, detail, onClose: () => {}, copiedId: null, onCopy: () => {} }));
  assert.match(html, /data-knowledge="unknown"/);
  assert.match(html, /data-knowledge="not_observed"/);
  assert.equal((html.match(/data-knowledge="confirmed_absent"/g) ?? []).length, 1);
  assert.ok(html.includes("Back to filtered list"));
  assert.doesNotMatch(html, /aria-modal="true"/);
});
