import assert from "node:assert/strict";
import { test } from "node:test";
import { formatPrComment } from "../src/lib/pr-comment.ts";

test("PR comment states introduced severity, gate effect and absolute finding link", () => {
  const comment = formatPrComment({
    title: "Crypto policy", result: "failure", gate_effect: "blocks",
    introduced: [{ finding_id: "finding_1", label: "RSA-1024", severity: "critical", href: "/finding?run_id=run_1&finding_id=finding_1" }],
  }, "https://qrypton.example");
  assert.match(comment, /Introduced findings:/);
  assert.match(comment, /CRITICAL.*RSA-1024/);
  assert.match(comment, /Policy gate: \*\*Blocks merge\*\*/);
  assert.match(comment, /https:\/\/qrypton\.example\/finding\?run_id=run_1&finding_id=finding_1/);
});

test("PR comment does not invent findings or a gate decision", () => {
  const comment = formatPrComment({
    title: "Crypto policy", result: "pending", gate_effect: "not_evaluated", introduced: [],
  }, "https://qrypton.example");
  assert.match(comment, /No introduced findings were reported/);
  assert.match(comment, /Not evaluated by the CI publisher/);
});
