import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import ts from "typescript";
import { TERMINAL_FAILURE, TERMINAL_SUCCESS } from "../src/lib/scan-polling.ts";

const require = createRequire(import.meta.url);
const code = ts.transpileModule(readFileSync(new URL("../src/components/scan-notifications.tsx", import.meta.url), "utf8"), {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS },
}).outputText;

test("completion tracking survives remount and never treats polling errors as failures", async () => {
  const saved = new Map();
  const timers = new Map();
  let effect;
  let updates = 0;
  let result = { status: "UNAVAILABLE", pollingError: true };
  const storage = { getItem: (key) => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value) };
  const browser = { dispatchEvent: () => {}, addEventListener: () => {}, removeEventListener: () => {},
    setInterval: (callback) => { timers.set(1, callback); return 1; }, clearInterval: (id) => timers.delete(id) };
  const load = () => {
    const compiledModule = { exports: {} };
    const dependencies = (name) => {
      if (name === "react") return { useEffect: (callback) => { effect = callback; }, useState: (initial) => [initial, () => {}] };
      if (name === "@/lib/api") return { API_BASE: "http://scan.test" };
      if (name === "@/lib/scan-polling") return { fetchScanStatus: async () => result, TERMINAL_FAILURE, TERMINAL_SUCCESS };
      return require(name);
    };
    new Function("require", "module", "exports", "window", "localStorage", code)(dependencies, compiledModule, compiledModule.exports, browser, storage);
    return compiledModule.exports;
  };
  const first = load();
  first.trackScan("run_persisted");
  // A new component/module instance represents returning to the page.
  const returned = load();
  returned.ScanNotifications({ onSettled: () => { updates++; } });
  const cleanup = effect();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(updates, 0);
  assert.equal(JSON.parse([...saved.values()][0])[0].outcome, null);
  result = { status: "PARTIAL", findings_discovered: 4 };
  timers.get(1)();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(updates, 1);
  assert.equal(JSON.parse([...saved.values()][0])[0].outcome, "PARTIAL");
  timers.get(1)();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(updates, 1);
  cleanup();
  assert.equal(timers.size, 0);
});
