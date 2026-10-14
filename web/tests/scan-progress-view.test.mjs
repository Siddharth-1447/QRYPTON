import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import ts from "typescript";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import * as polling from "../src/lib/scan-polling.ts";

const require = createRequire(import.meta.url);
const source = readFileSync(new URL("../src/components/scan-progress.tsx", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } });
const compiledModule = { exports: {} };
const logoSource = readFileSync(new URL("../src/components/logo.tsx", import.meta.url), "utf8");
const logoCompiled = ts.transpileModule(logoSource, { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS } });
const logoModule = { exports: {} };
new Function("require", "module", "exports", logoCompiled.outputText)(name => name === "@/lib/utils" ? { cn: (...classes) => classes.filter(Boolean).join(" ") } : require(name), logoModule, logoModule.exports);
new Function("require", "module", "exports", compiled.outputText)(name => name === "@/lib/scan-polling" ? polling : name === "./logo" ? logoModule.exports : require(name), compiledModule, compiledModule.exports);
const { ScanProgress, SCAN_STAGES } = compiledModule.exports;
const render = (progress) => renderToStaticMarkup(React.createElement(ScanProgress, { progress }));

test("all eight stages have readable states, including warnings and failures", () => {
  const stages = ["completed", "completed", "warning", "failed", "running", "pending", "pending", "pending"];
  const html = render({ status: "RUNNING", stages, findings_discovered: 12 });
  for (const label of SCAN_STAGES) assert.ok(html.includes(label));
  for (const state of new Set(stages)) assert.ok(html.includes(`data-state="${state}"`));
  assert.match(html, /aria-current="step"/);
  assert.match(html, /2 of 8 stages confirmed complete/);
  assert.doesNotMatch(html, /Inspection complete/);
  assert.match(html, />12<\/span>/);
  assert.match(html, /aria-label="QRYPTON"/);
  assert.match(html, /analyses artifacts; it does not execute them\./);
});

test("unreported counts and stages are explicit rather than manufactured", () => {
  const html = render(null);
  assert.match(html, /Waiting for the first confirmed finding count/);
  assert.equal((html.match(/data-state="pending"/g) ?? []).length, 8);
  assert.doesNotMatch(html, /data-state="completed"/);
});

test("a confirmed zero count and partial completion remain visible", () => {
  const html = render({ status: "PARTIAL", findings_discovered: 0 });
  assert.match(html, />0<\/span>/);
  assert.match(html, /Results ready with coverage warnings/);
  assert.doesNotMatch(html, /Inspection complete/);
});

test("result reveal requires an explicit successful terminal status", () => {
  for (const status of ["RUNNING", "FAILED", "ERROR", "UNAVAILABLE"]) {
    assert.doesNotMatch(render({ status, stages: Array(8).fill("completed") }), /Inspection complete/);
  }
  for (const status of polling.TERMINAL_SUCCESS) {
    assert.match(render({ status }), /Results ready|Results ready with coverage warnings/);
  }
});

test("workflow uses bounded state transitions and global reduced-motion protection", () => {
  const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
  assert.match(css, /scan-node-arrive var\(--duration-base\)/);
  assert.match(css, /\*, \*::before, \*::after \{ animation: none !important; transition-duration: 0ms !important/);
  assert.doesNotMatch(css, /scan-shimmer/);
  assert.match(css, /qrypton-logo-float[^\n]+infinite/);
});
