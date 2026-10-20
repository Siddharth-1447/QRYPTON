# Scan worker lifecycle

The FastAPI service runs scans in a process-local thread executor. SQLite stores
scan summaries, finalized results, and worker heartbeats; it is not a durable job
queue. The API and dashboards are intended for trusted local evaluation.

## Submission and completion

`POST /api/v1/scans` validates the request and records a queued scan before
submitting the worker. The executor has two worker threads. Submission failure
records a sanitized terminal failure and returns HTTP 503.

The worker owns target resolution, service configuration, orchestration, failure
persistence, and activity cleanup. It marks the scan running and maintains a
heartbeat while active. Resolution, configuration, scanner, and orchestration
failures remain explicit rather than being converted to successful empty scans.
If the database itself is unavailable, terminal persistence can fail; the worker
logs that failure and still clears its process-local activity registration.

Finalized snapshots cannot be overwritten by restarting the same run. Analyst
status and ownership are separate records. Explicit scan deletion remains
available; immutability does not imply permanent retention.

## Scheduling and timeouts

Source discovery, parsing, binary inspection, hashing, and entropy calculations
offload blocking work to threads where implemented. Scanner loops yield and
check cancellation at cooperative checkpoints. Archive extraction cleans up its
temporary directory when cancelled or when extraction fails.

| API target | Execution budget |
| --- | ---: |
| Source repository or source archive | 90 seconds |
| Binary, library, container, or cloud KMS input | 1,200 seconds |

The worker uses the smaller of the target budget and the explicit scan limit.
Despite the helper name `_size_scaled_timeout_seconds`, input size does not
change these budgets. Mosca duration inputs are required to be finite values in
`[0, 10000]` before work is submitted.

These are cooperative execution budgets. Cancellation cannot forcibly stop an
OS read or a native parser already running in a thread, and executor shutdown
can wait for that work to return. Target acquisition precedes the execution
watchdog; normalization, assessment, and persistence retain synchronous work.
This implementation does not guarantee an end-to-end wall-time or memory bound.
Archive and container resource enforcement also varies by adapter.

## Heartbeats and orphan handling

The `qrypton_run_heartbeats` table records active worker timestamps. The heartbeat
interval is the smaller of 10 seconds and one third of the orphan grace period.
`QRYPTON_SCAN_ORPHAN_GRACE_SECONDS` defaults to 60 seconds; invalid, nonfinite, or
nonpositive values use that default.

Polling expires a running scan only when no local worker registration exists
and its persisted heartbeat is older than the grace period. A legacy running row
without a heartbeat receives one grace period on first observation. A
conditional database update prevents a stale poll from replacing a completed
result. Queued rows remain queued when no worker owns them.

A heartbeat establishes liveness rather than forward progress. The queue does
not recover work after a process restart, so abandoned queued rows require
operator review. Persisted heartbeats reduce false orphan detection across API
processes; they do not establish supported multi-worker deployment.

## Dashboard polling and recovery

The dashboard status monitor uses a 5-second request timeout, a 1.5-second polling
interval, and a 15-minute overall monitoring deadline. Three consecutive status
errors stop monitoring; a valid response resets that error counter. HTTP errors,
malformed status payloads, and network failures remain visible.

A monitoring failure does not cancel the backend scan. Retain the scan ID and
check Scan History once connectivity returns. Partial results remain partial
and need scope review before absent findings are treated as resolved.

## Relevant code and checks

- [`api/app.py`](../src/qrypton/api/app.py): submission, worker guards, watchdog,
  heartbeat, and status handling.
- [`storage/sqlite.py`](../src/qrypton/storage/sqlite.py): run persistence and
  heartbeat schema.
- [`scan-polling.ts`](../web/src/lib/scan-polling.ts): bounded dashboard monitoring.
- [`test_worker_lifecycle.py`](../tests/api/test_worker_lifecycle.py),
  [`test_queue_ownership.py`](../tests/api/test_queue_ownership.py), and
  [`test_async_scanners.py`](../tests/scanners/test_async_scanners.py): backend
  lifecycle, queue, and cooperative cancellation checks.
- [`scan-polling.test.mjs`](../web/tests/scan-polling.test.mjs): monitoring errors,
  retry bounds, and deadline behavior.

Use the [contribution checks](../CONTRIBUTING.md) for current verification.
