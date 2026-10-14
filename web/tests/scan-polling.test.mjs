import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";
import {
  fetchScanStatus,
  pollScanUntilSettled,
  SCAN_POLL_MAX_DURATION_MS,
  SCAN_STATUS_TIMEOUT_MS,
} from "../src/lib/scan-polling.ts";

afterEach(() => mock.restoreAll());
const apiBase = "http://scan.test";

test("polling delivers real stage states and counts, preserving zero", async () => {
  const stages = ["completed", "completed", "completed", "completed", "running", "pending", "pending", "pending"];
  mock.method(globalThis, "fetch", async () => Response.json({ status: "RUNNING", stages, findings_discovered: 0 }));
  const result = await fetchScanStatus(apiBase, "run_test");
  assert.deepEqual(result.stages, stages);
  assert.equal(result.findings_discovered, 0);
});

test("missing and invalid telemetry never manufactures stages or counts", async () => {
  for (const payload of [{}, { stages: ["completed"], findings_discovered: -1 }, { stages: Array(8).fill("fiction"), findings_discovered: 1.5 }]) {
    mock.method(globalThis, "fetch", async () => Response.json({ status: "RUNNING", ...payload }));
    const result = await fetchScanStatus(apiBase, "run_test");
    assert.equal(result.stages, undefined);
    assert.equal(result.findings_discovered, undefined);
  }
});

test("terminal snapshots reach the live view before polling settles", async () => {
  const snapshots = [];
  const terminal = { status: "PARTIAL", stages: Array(8).fill("warning"), findings_discovered: 7 };
  await pollScanUntilSettled(apiBase, "run_test", (_, __, snapshot) => snapshots.push(snapshot), { fetchStatus: async () => terminal });
  assert.deepEqual(snapshots, [terminal]);
});

for (const status of [404, 401, 429, 500, 503]) {
  test(`HTTP ${status} is an explicit polling error without posture fallback`, async () => {
    const fetch = mock.method(globalThis, "fetch", async () => new Response("", { status }));
    const result = await fetchScanStatus(apiBase, "run_test");
    assert.equal(result.pollingError, true);
    assert.equal(result.status, status >= 500 ? "UNAVAILABLE" : "ERROR");
    assert.equal(fetch.mock.callCount(), 1);
  });
}

for (const payload of [null, {}, { status: "mystery" }, { status: 123 }]) {
  test(`malformed status ${JSON.stringify(payload)} counts as an error`, async () => {
    mock.method(globalThis, "fetch", async () => Response.json(payload));
    const result = await fetchScanStatus(apiBase, "run_test");
    assert.equal(result.pollingError, true);
    assert.equal(result.status, "ERROR");
  });
}

test("invalid JSON is an explicit error", async () => {
  mock.method(globalThis, "fetch", async () => new Response("not json"));
  assert.equal((await fetchScanStatus(apiBase, "run_test")).pollingError, true);
});

test("connection loss stops after three requests", async () => {
  const fetch = mock.method(globalThis, "fetch", async () => { throw new TypeError("offline"); });
  let clock = 0;
  const messages = [];
  const result = await pollScanUntilSettled(apiBase, "run_saved", (_, text) => messages.push(text), {
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
  });
  assert.equal(fetch.mock.callCount(), 3);
  assert.equal(result.status, "FAILED");
  assert.match(result.message, /3 consecutive status errors/);
  assert.match(result.message, /run_saved/);
  assert.equal(messages.length, 2);
});

test("HTTP errors stop after three requests", async () => {
  const fetch = mock.method(globalThis, "fetch", async () => new Response("", { status: 500 }));
  const result = await pollScanUntilSettled(apiBase, "run_test", undefined, { sleep: async () => {} });
  assert.equal(fetch.mock.callCount(), 3);
  assert.equal(result.status, "FAILED");
  assert.match(result.message, /HTTP 500/);
});

test("a hanging network request is aborted and reported as unavailable", async () => {
  let signal;
  mock.method(globalThis, "fetch", async (_, options) => {
    signal = options.signal;
    return new Promise((_, reject) => signal.addEventListener("abort", () => reject(signal.reason)));
  });
  // AbortSignal.timeout is unref'ed by Node; keep this test alive until it fires.
  const keepAlive = setTimeout(() => {}, 1000);
  try {
    const result = await fetchScanStatus(apiBase, "run_test", 5);
    assert.equal(signal.aborted, true);
    assert.equal(result.status, "UNAVAILABLE");
    assert.equal(result.pollingError, true);
  } finally {
    clearTimeout(keepAlive);
  }
});

test("three consecutive timeouts stop polling", async () => {
  let calls = 0;
  const result = await pollScanUntilSettled(apiBase, "run_test", undefined, {
    fetchStatus: async () => { calls++; throw new DOMException("Timed out", "TimeoutError"); },
    sleep: async () => {},
  });
  assert.equal(calls, 3);
  assert.equal(result.status, "FAILED");
});

test("a valid active status resets consecutive errors", async () => {
  const results = [
    { status: "ERROR", pollingError: true }, { status: "UNAVAILABLE", pollingError: true },
    { status: "QUEUED" },
    { status: "UNAVAILABLE", pollingError: true }, { status: "ERROR", pollingError: true },
    { status: "COMPLETED" },
  ];
  let calls = 0;
  const result = await pollScanUntilSettled(apiBase, "run_test", undefined, {
    fetchStatus: async () => results[calls++], sleep: async () => {},
  });
  assert.equal(calls, 6);
  assert.equal(result.status, "COMPLETED");
});

for (const status of ["PARTIAL", "COMPLETED", "FAILED", "ERROR"]) {
  test(`a retrieved terminal ${status} run stops immediately`, async () => {
    const fetch = mock.method(globalThis, "fetch", async () => Response.json({ status, message: "details" }));
    const result = await pollScanUntilSettled(apiBase, "run_test");
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal(result.status, status);
    assert.equal(result.message, "details");
    assert.equal(result.pollingError, undefined);
  });
}

test("healthy running responses still stop at the 15 minute deadline", async () => {
  let clock = 0;
  const budgets = [];
  const result = await pollScanUntilSettled(apiBase, "run_test", undefined, {
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
    fetchStatus: async (_, __, timeoutMs) => {
      budgets.push(timeoutMs);
      assert.ok(timeoutMs <= SCAN_STATUS_TIMEOUT_MS);
      assert.ok(timeoutMs <= SCAN_POLL_MAX_DURATION_MS - clock);
      clock += timeoutMs;
      return { status: "RUNNING" };
    },
  });
  assert.equal(clock, SCAN_POLL_MAX_DURATION_MS);
  assert.equal(result.status, "FAILED");
  assert.match(result.message, /15 minutes/);
  assert.ok(budgets.at(-1) < SCAN_STATUS_TIMEOUT_MS);
});
