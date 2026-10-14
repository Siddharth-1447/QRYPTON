import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";
import { networkSampleModeEnabled } from "../src/lib/network-sample.ts";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const require = createRequire(import.meta.url);

test("network sample mode is explicitly opt-in and gates navigation and rendering", () => {
  assert.equal(networkSampleModeEnabled(undefined), false);
  assert.equal(networkSampleModeEnabled("0"), false);
  assert.equal(networkSampleModeEnabled("1"), true);
  assert.match(source("../src/components/sidebar.tsx"), /NETWORK_SAMPLE_MODE \? \[\{ id: "live-scanner"/);
  assert.match(source("../src/app/page.tsx"), /NETWORK_SAMPLE_MODE \? <LiveTelemetry \/>/);
});

test("sample mode keeps a non-dismissible simulated-data banner", () => {
  const component = source("../src/components/live-telemetry.tsx");
  assert.match(component, /SIMULATED DATA — sample mode; no network traffic was inspected/);
  assert.match(component, /role="status"/);
  assert.match(source("../src/app/globals.css"), /\.qrypton-simulated-banner \{ position: sticky;/);
  const compiled = ts.transpileModule(component, {
    compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const compiledModule = { exports: {} };
  const load = (name) => {
    if (name === "@/components/ui/primitives") {
      return { Badge: ({ children }) => React.createElement("span", null, children) };
    }
    if (name === "@/components/telemetry-chart") {
      return { TelemetryChart: () => React.createElement("div") };
    }
    return require(name);
  };
  new Function("require", "module", "exports", compiled)(load, compiledModule, compiledModule.exports);
  const html = renderToStaticMarkup(React.createElement(compiledModule.exports.LiveTelemetry));
  assert.match(html, /role="status"[^>]*>SIMULATED DATA — sample mode; no network traffic was inspected/);
});

test("seeded network counters never enter export, CBOM, PDF, or dashboard KPI paths", () => {
  const walk = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap(
    (entry) => entry.isDirectory() ? walk(join(directory, entry.name)) : [join(directory, entry.name)]
  );
  const code = ["../src", "../../src/qrypton"].flatMap(
    (path) => walk(fileURLToPath(new URL(path, import.meta.url)))
  );
  for (const path of code.filter((item) => /\.(?:tsx?|py)$/.test(item))) {
    if (path.endsWith("live-telemetry.tsx")) continue;
    assert.doesNotMatch(readFileSync(path, "utf8"), /\b(?:48213|1174|326)\b/, path);
  }
});
