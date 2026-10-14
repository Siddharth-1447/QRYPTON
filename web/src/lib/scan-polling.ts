/** Bounded status polling shared by the scan workflow and its regression tests. */
export const SCAN_POLL_INTERVAL_MS = 1500;
export const SCAN_POLL_MAX_DURATION_MS = 15 * 60 * 1000;
export const SCAN_STATUS_TIMEOUT_MS = 5000;
export const SCAN_POLL_MAX_ERRORS = 3;
export const TERMINAL_SUCCESS = new Set(["COMPLETED", "COMPLETE", "SUCCESS", "PARTIAL"]);
export const TERMINAL_FAILURE = new Set(["FAILED", "FAILURE", "ERROR"]);
const ACTIVE_STATUSES = new Set(["QUEUED", "PENDING", "RUNNING", "IN_PROGRESS"]);

export interface ScanStatus {
  status: string;
  stages?: Array<"pending" | "running" | "completed" | "warning" | "failed">;
  findings_discovered?: number;
  exit_code?: number;
  message?: string;
  /** Distinguish a polling error from a successfully retrieved FAILED/ERROR run. */
  pollingError?: boolean;
}

export function normalizeScanStatus(value: unknown): string {
  return typeof value === "string" ? value.trim().toUpperCase().replace(/[\s-]+/g, "_") : "";
}

export function formatElapsedTime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export function getScanPhaseMessage(elapsedMs: number, status?: string): string {
  const formatted = formatElapsedTime(elapsedMs);
  if (status === "QUEUED" || status === "PENDING") return `Scan queued in background · Waiting for ${formatted}...`;
  return `Scan running · Elapsed ${formatted}. Waiting for backend updates.`;
}

export async function fetchScanStatus(
  apiBase: string, scanId: string, timeoutMs = SCAN_STATUS_TIMEOUT_MS,
): Promise<ScanStatus> {
  try {
    const response = await fetch(`${apiBase}/api/v1/scans/${encodeURIComponent(scanId)}`, {
      signal: AbortSignal.timeout(Math.max(1, Math.ceil(timeoutMs))),
      cache: "no-store",
    });
    if (!response.ok) {
      return {
        status: response.status >= 500 ? "UNAVAILABLE" : "ERROR", pollingError: true,
        message: `Scan status request failed (HTTP ${response.status}).`,
      };
    }
    const data: unknown = await response.json();
    if (!data || typeof data !== "object") {
      return { status: "ERROR", pollingError: true, message: "Invalid scan status response." };
    }
    const payload = data as Record<string, unknown>;
    const status = normalizeScanStatus(payload.status ?? payload.run_status);
    if (!ACTIVE_STATUSES.has(status) && !TERMINAL_SUCCESS.has(status) && !TERMINAL_FAILURE.has(status)) {
      return { status: "ERROR", pollingError: true, message: "Unrecognized scan status response." };
    }
    return {
      status,
      stages: Array.isArray(payload.stages) && payload.stages.length === 8 && payload.stages.every((s) => ["pending", "running", "completed", "warning", "failed"].includes(s)) ? payload.stages as ScanStatus["stages"] : undefined,
      findings_discovered: typeof payload.findings_discovered === "number" && Number.isSafeInteger(payload.findings_discovered) && payload.findings_discovered >= 0 ? payload.findings_discovered : undefined,
      exit_code: typeof payload.exit_code === "number" ? payload.exit_code : undefined,
      message: typeof payload.message === "string" ? payload.message : undefined,
    };
  } catch {
    return {
      status: "UNAVAILABLE", pollingError: true,
      message: "Cannot reach the scan service or the status request timed out.",
    };
  }
}

interface PollOptions {
  // Injectable clock and I/O make deadline and retry tests deterministic.
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  fetchStatus?: (apiBase: string, scanId: string, timeoutMs: number) => Promise<ScanStatus>;
}

export async function pollScanUntilSettled(
  apiBase: string,
  scanId: string,
  onProgress?: (elapsedMs: number, message: string, snapshot?: ScanStatus) => void,
  options: PollOptions = {},
): Promise<ScanStatus> {
  const now = options.now ?? (() => performance.now());
  const sleep = options.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const fetchStatus = options.fetchStatus ?? fetchScanStatus;
  const startedAt = now();
  const deadline = startedAt + SCAN_POLL_MAX_DURATION_MS;
  let consecutiveErrors = 0;
  while (now() < deadline) {
    let result: ScanStatus;
    try {
      result = await fetchStatus(apiBase, scanId, Math.min(SCAN_STATUS_TIMEOUT_MS, deadline - now()));
    } catch {
      result = { status: "UNAVAILABLE", pollingError: true, message: "Scan status request failed." };
    }
    const elapsed = now() - startedAt;
    if (now() >= deadline) break;
    if (result.pollingError || result.status === "UNAVAILABLE") {
      consecutiveErrors += 1;
      const detail = result.message ?? "The scan service is unavailable.";
      if (consecutiveErrors >= SCAN_POLL_MAX_ERRORS) {
        return {
          status: "FAILED", pollingError: true,
          message: `Stopped checking scan ${scanId} after ${SCAN_POLL_MAX_ERRORS} consecutive status errors. ${detail} Check your connection and open Scan History to retry checking this run; it may still be running.`,
        };
      }
      onProgress?.(elapsed, `${detail} Retrying (${consecutiveErrors}/${SCAN_POLL_MAX_ERRORS})...`);
    } else {
      consecutiveErrors = 0;
      onProgress?.(elapsed, result.message || getScanPhaseMessage(elapsed, result.status), result);
      if (TERMINAL_SUCCESS.has(result.status) || TERMINAL_FAILURE.has(result.status)) return result;
    }
    await sleep(Math.min(SCAN_POLL_INTERVAL_MS, Math.max(0, deadline - now())));
  }
  return {
    status: "FAILED", pollingError: true,
    message: `Stopped checking scan ${scanId} after 15 minutes. Check Scan History for its current status; the backend scan may still be running.`,
  };
}
