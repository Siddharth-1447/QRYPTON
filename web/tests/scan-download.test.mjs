import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";

const source = ts.transpileModule(readFileSync(new URL("../src/lib/scan-download.ts", import.meta.url), "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;

function harness(failure) {
  const requests = [], downloads = [];
  const compiledModule = { exports: {} };
  const fetch = async (url, options) => {
    requests.push({ url, options });
    return { ok: !url.includes(failure ?? "never-fail"), status: 503, json: async () => ({ detail: "Report unavailable" }), blob: async () => ({ size: 10 }) };
  };
  const document = { createElement: () => ({ click() { downloads.push(this.download); }, remove() {} }), body: { appendChild() {} } };
  new Function("require", "module", "exports", "fetch", "document", "URL", "setTimeout", source)(() => ({ API_BASE: "http://test", accessHeaders: () => ({ Authorization: "Bearer test" }) }), compiledModule, compiledModule.exports, fetch, document, { createObjectURL: () => "blob:test", revokeObjectURL() {} }, fn => fn());
  return { ...compiledModule.exports, requests, downloads };
}

test("opt-out never requests a report", async () => {
  const h = harness();
  assert.equal(await h.downloadScanReports("run-new", "none"), "");
  assert.equal(h.requests.length, 0);
});
test("all downloads are bound to the completed scan and authorized", async () => {
  const h = harness();
  await h.downloadScanReports("run-new", "all");
  assert.equal(h.downloads.length, 3);
  assert.ok(h.requests.every(r => r.url.includes("/scans/run-new/") && r.options.headers.Authorization === "Bearer test"));
  assert.ok(h.downloads.some(name => name.endsWith(".pdf")));
  assert.ok(h.downloads.some(name => name.endsWith(".cdx.json")));
  assert.ok(h.downloads.some(name => name.endsWith(".csv")));
});
test("one failed format does not suppress the other formats or mark the scan failed", async () => {
  const h = harness("report/pdf");
  const message = await h.downloadScanReports("run-new", "all");
  assert.match(message, /Scan saved.*PDF: Report unavailable/);
  assert.equal(h.downloads.length, 2);
});
