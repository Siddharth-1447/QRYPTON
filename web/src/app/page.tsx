"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import { ScanWorkflow, DEFAULT_SCAN_FORM, describeScanTarget, buildTargetSource, buildArtifactMetadata, type ScanForm } from "@/components/scan-workflow";
import { CryptoInventory } from "@/components/crypto-inventory";
import { FindingDetail } from "@/components/finding-detail";
import { RiskPrioritization } from "@/components/risk-prioritization";
import { LiveTelemetry } from "@/components/live-telemetry";
import { ScanHistory, DEFAULT_SCANS, type ScanHistoryRecord } from "@/components/scan-history";
import { Sidebar, NAV_SECTIONS, SIDEBAR_DEFAULT_WIDTH } from "@/components/sidebar";
import { CryptoLockVisual } from "@/components/crypto-lock-visual";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Search,
  Loader2,
  XCircle,
  CheckCircle2,
  Layers,
  ChevronRight,
  X,
  Plus,
  ArrowDown,
} from "lucide-react";

// --- API Domain Types ---

interface ExecutivePosture {
  total_findings: number;
  unique_asset_ids: number;
  critical_findings_count: number;
  high_findings_count: number;
  medium_findings_count: number;
  low_findings_count: number;
  informational_findings_count: number;
  unassessed_findings_count: number;
  run_status: string;
  scanner_failed_count: number;
  scanner_partial_count: number;
  policy_passed: boolean;
  policy_violations: string[];
}

interface InventoryRow {
  finding_id: string;
  category: string;
  algorithm_name: string | null;
  algorithm_family: string | null;
  key_size_bits: number | null;
  lifecycle_status: string | null;
  risk_level: "critical" | "high" | "medium" | "low" | "informational";
  risk_score: number | null;
  confidence: number;
  evidence_count: number;
  first_observed_at: string;
  last_observed_at: string;
}

interface RiskHeatmapCell {
  mosca_urgency: "critical" | "high" | "medium" | "low";
  business_criticality: "critical" | "high" | "medium" | "low" | "unclassified";
  finding_count: number;
  finding_ids: string[];
}

interface MoscaPoint {
  finding_id: string;
  urgency: "critical" | "high" | "medium" | "low";
  exposure_score: number | null;
  x_data_lifetime_years: number | null;
  y_migration_years: number | null;
  z_crqc_horizon_years: number | null;
  required_security_years: number | null;
  time_margin_years: number | null;
  timeline_state: "persisted" | "unavailable";
}

interface RoadmapRow {
  finding_id: string;
  priority: number;
  action: string;
  role: string | null;
  target_algorithms: string[];
  hybrid_mode: string | null;
  blocking_conditions: string[];
  standards_references: string[];
}

interface FindingDetail {
  finding: {
    id: string;
    category: string;
    confidence: number;
    first_observed_at: string;
    last_observed_at: string;
    algorithm?: {
      value?: {
        canonical_name?: string;
        family?: string;
        key_size_bits?: { value?: number };
        lifecycle_status?: string;
      };
    };
    provenance?: {
      scanner_name?: string;
      scanner_version?: string;
      observed_at?: string;
    };
  };
  assessment?: {
    score?: { value?: number };
    level?: string;
    factors?: {
      rationale?: string[];
      cryptographic_obsolescence?: { value?: number };
      quantum_exposure?: { value?: number };
      exploitability?: { value?: number };
      business_impact?: { value?: number };
    };
  } | null;
  evidence_provenance: Array<{
    id: string;
    kind: string;
    confidence: number;
    location?: {
      relative_path?: string;
      line_start?: number;
      line_end?: number;
      symbol?: string;
    };
    excerpt?: string;
  }>;
  recommendations: Array<{
    id: string;
    priority: number;
    title: string;
    action: string;
    nist_references?: string[];
    replacement_algorithm?: {
      value?: {
        canonical_name?: string;
      };
    };
  }>;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const RESULTS_SECTION_ID = "results-section";
const TERMINAL_SUCCESS = new Set(["COMPLETED", "COMPLETE", "SUCCESS", "PARTIAL"]);
const TERMINAL_FAILURE = new Set(["FAILED", "FAILURE", "ERROR"]);

// --- Dynamic scan timeouts by target type ---
export const SCAN_TIMEOUT_DEFAULT_MS = 15000; // Archives, Binaries, Manifests, KMS
export const SCAN_TIMEOUT_MEDIUM_MS = 60000; // Source Repositories
export const SCAN_TIMEOUT_EXTENDED_MS = 120000; // Container Images, Heavy Repos
export const SCAN_POLL_INTERVAL_MS = 1500;

const HEAVY_REPO_HINT = /(monorepo|heavy|large|enterprise|chromium|linux|kernel|opencv|tensorflow)/i;

export function getScanTimeoutForTarget(targetType: string, repository?: string): number {
  const normalized = String(targetType ?? "").trim().toLowerCase();
  if (normalized === "container_image") return SCAN_TIMEOUT_EXTENDED_MS;
  if (normalized === "source_repo") {
    const repo = String(repository ?? "");
    const isHeavy =
      HEAVY_REPO_HINT.test(repo) || repo.length > 80 || (repo.match(/\//g) ?? []).length > 4;
    return isHeavy ? SCAN_TIMEOUT_EXTENDED_MS : SCAN_TIMEOUT_MEDIUM_MS;
  }
  return SCAN_TIMEOUT_DEFAULT_MS;
}

export function getScanPhaseMessage(elapsedMs: number): string {
  if (elapsedMs < 5000) return "Connecting to target & initializing engine...";
  if (elapsedMs < 15000) return "Fetching remote assets & parsing static patterns...";
  return "Deep AST analysis & generating CycloneDX 1.6 CBOM...";
}

function normalizeScanStatus(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, "_");
}

function extractScanId(payload: Record<string, unknown> | null | undefined): string | null {
  if (!payload) return null;
  for (const key of ["scan_id", "run_id", "id"]) {
    const value = payload[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function fetchScanStatus(
  scanId: string,
  timeoutMs: number = SCAN_TIMEOUT_DEFAULT_MS
): Promise<{ status: string; exit_code?: number; message?: string }> {
  let scanRes: Response;
  try {
    scanRes = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(scanId)}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new Error(`Backend unreachable at ${API_BASE}. Scan service is not running.`);
  }
  if (scanRes.ok) {
    const data = (await scanRes.json()) as Record<string, unknown>;
    const status = normalizeScanStatus(data.status ?? data.run_status);
    const exitCode = typeof data.exit_code === "number" ? data.exit_code : undefined;
    const message = typeof data.message === "string" ? data.message : undefined;
    return { status, exit_code: exitCode, message };
  }
  const postureRes = await fetch(`${API_BASE}/api/v1/posture?run_id=${encodeURIComponent(scanId)}`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (postureRes.ok) {
    const data = (await postureRes.json()) as Record<string, unknown>;
    return { status: normalizeScanStatus(data.run_status) };
  }
  throw new Error(`Backend unreachable — unable to read scan status. Ensure the scan service is running at ${API_BASE}.`);
}

async function pollScanUntilSettled(
  scanId: string,
  timeoutMs: number = SCAN_TIMEOUT_DEFAULT_MS,
  onProgress?: (elapsedMs: number, message: string) => void
): Promise<{ status: string; exit_code?: number; message?: string }> {
  const startedAt = Date.now();
  const maxAttempts = Math.max(1, Math.ceil(timeoutMs / SCAN_POLL_INTERVAL_MS));
  let last: { status: string; exit_code?: number; message?: string } = { status: "RUNNING" };
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const elapsed = Date.now() - startedAt;
    onProgress?.(elapsed, getScanPhaseMessage(elapsed));
    try {
      last = await fetchScanStatus(scanId, timeoutMs);
      if (TERMINAL_SUCCESS.has(last.status) || TERMINAL_FAILURE.has(last.status)) {
        onProgress?.(Date.now() - startedAt, getScanPhaseMessage(Date.now() - startedAt));
        return last;
      }
    } catch (err) {
      throw err;
    }
    if (attempt < maxAttempts - 1) {
      await wait(SCAN_POLL_INTERVAL_MS);
    }
  }
  throw new Error(
    `Scan service did not respond after ${timeoutMs}ms. The backend may be unreachable. Please check that uvicorn is running.`
  );
}

const DEFAULT_POSTURE: ExecutivePosture = {
  total_findings: 0,
  unique_asset_ids: 0,
  critical_findings_count: 0,
  high_findings_count: 0,
  medium_findings_count: 0,
  low_findings_count: 0,
  informational_findings_count: 0,
  unassessed_findings_count: 0,
  run_status: "NOT_STARTED",
  scanner_failed_count: 0,
  scanner_partial_count: 0,
  policy_passed: false,
  policy_violations: [],
};

const DEFAULT_INVENTORY: InventoryRow[] = [];

export default function QryptonCommandCenter() {
  const router = useRouter();
  // --- Data State ---
  const [posture, setPosture] = useState<ExecutivePosture | null>(DEFAULT_POSTURE);
  const [inventory, setInventory] = useState<InventoryRow[]>(DEFAULT_INVENTORY);
  const [moscaPoints, setMoscaPoints] = useState<MoscaPoint[]>([]);
  const [heatmap, setHeatmap] = useState<RiskHeatmapCell[]>([]);
  const [roadmap, setRoadmap] = useState<RoadmapRow[]>([]);

  const [loading, setLoading] = useState<boolean>(false);
  const [authReady, setAuthReady] = useState<boolean>(false);
  const [, setRefreshing] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const [theme] = useState<"light" | "dark">("dark");
  const [sidebarWidth, setSidebarWidth] = useState(SIDEBAR_DEFAULT_WIDTH);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("dashboard");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  useEffect(() => {
    const sessionActive = window.localStorage.getItem("qrypton.session") === "active" || window.sessionStorage.getItem("qrypton.session") === "active";
    if (sessionActive) {
      queueMicrotask(() => setAuthReady(true));
    } else {
      router.replace("/login");
    }
  }, [router]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => entries.forEach((entry) => entry.isIntersecting && setActiveSection(entry.target.id)),
      { rootMargin: "-25% 0px -60% 0px" }
    );
    NAV_SECTIONS.forEach(({ id }) => document.getElementById(id) && observer.observe(document.getElementById(id)!));
    return () => observer.disconnect();
  }, []);

  const navigateTo = useCallback((id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  }, []);

  const [scanPolling, setScanPolling] = useState<boolean>(false);
  const [scanPhaseMessage, setScanPhaseMessage] = useState<string | null>(null);
  const [scanElapsedMs, setScanElapsedMs] = useState<number>(0);
  const [activeScanMeta, setActiveScanMeta] = useState<{
    id: string;
    target: string;
    target_type: string;
    environment: string;
  } | null>(null);

  // --- Filter & Drawer State ---
  const [search, setSearch] = useState<string>("");
  const [selectedHeatmapCell, setSelectedHeatmapCell] = useState<{
    urgency: string;
    criticality: string;
    finding_ids?: string[];
  } | null>(null);

  const [findingDetail, setFindingDetail] = useState<FindingDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // --- Scan Modal State ---
  const [isScanModalOpen, setIsScanModalOpen] = useState<boolean>(false);
  const [scanSubmitting, setScanSubmitting] = useState<boolean>(false);
  const [scanSuccessMessage, setScanSuccessMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>(DEFAULT_SCANS);

  const [scanForm, setScanForm] = useState<ScanForm>(DEFAULT_SCAN_FORM);

  const refreshScanHistory = useCallback(async () => {
    const response = await fetch(`${API_BASE}/api/v1/scans`);
    if (!response.ok) throw new Error("Unable to load persisted scan history.");
    const rows = await response.json() as Array<Record<string, unknown>>;
    setScanHistory(rows.map((row) => ({
      id: String(row.scan_id ?? row.run_id ?? ""),
      timestamp: String(row.completed_at ?? row.started_at ?? ""),
      target: String(row.artifact ?? "unavailable"),
      target_type: String(row.target_type ?? "unknown"),
      environment: String(row.environment ?? "unknown"),
      criticalCount: Number(row.critical_findings_count ?? 0),
      highCount: Number(row.high_findings_count ?? 0),
      mediumCount: Number(row.medium_findings_count ?? 0),
      totalFindings: Number(row.total_findings ?? 0),
      status: (normalizeScanStatus(row.status) === "PENDING" ? "RUNNING" : normalizeScanStatus(row.status)) as ScanHistoryRecord["status"],
    })).filter((row) => row.id));
  }, []);

  const deleteHistoricalScan = useCallback(async (scanId: string) => {
    const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
    if (!response.ok) {
      setApiError("Unable to delete the selected scan.");
      return;
    }
    if (activeScanId === scanId) {
      setActiveScanId(null);
      setActiveScanMeta(null);
    }
    await refreshScanHistory();
  }, [activeScanId, refreshScanHistory]);

  const revealResults = useCallback((scanId: string) => {
    setActiveScanId(scanId);
    setActiveSection(RESULTS_SECTION_ID);
    try {
      const url = new URL(window.location.href);
      url.searchParams.set("id", scanId);
      url.hash = RESULTS_SECTION_ID;
      window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
    } catch {
      // Non-browser environment — skip URL sync but still scroll below.
    }
    window.requestAnimationFrame(() => {
      document.getElementById(RESULTS_SECTION_ID)?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, []);

  // --- Data Fetching (per-scan when runId is provided) ---
  const loadData = useCallback(async (isSilent = false, runId?: string | null) => {
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);
      setApiError(null);

      const suffix = runId ? `?run_id=${encodeURIComponent(runId)}` : "";
      const [postureRes, invRes, moscaRes, heatmapRes, roadmapRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/posture${suffix}`),
        fetch(`${API_BASE}/api/v1/inventory${suffix}`),
        fetch(`${API_BASE}/api/v1/mosca/eval${suffix}`),
        fetch(`${API_BASE}/api/v1/risk${suffix}`),
        fetch(`${API_BASE}/api/v1/roadmap${suffix}`),
      ]);

      if (!postureRes.ok || !invRes.ok) {
        throw new Error(`Failed to load data from backend (${postureRes.status})`);
      }

      const [postureData, invData, moscaData, heatmapData, roadmapData] = await Promise.all([
        postureRes.json(),
        invRes.json(),
        moscaRes.ok ? moscaRes.json() : [],
        heatmapRes.ok ? heatmapRes.json() : [],
        roadmapRes.ok ? roadmapRes.json() : [],
      ]);

      setPosture(postureData);
      setInventory(invData || []);
      setMoscaPoints(moscaData || []);
      setHeatmap(Array.isArray(heatmapData) ? heatmapData : (heatmapData?.cells || []));
      setRoadmap(roadmapData || []);
      return postureData as ExecutivePosture;
    } catch {
      // Backend offline fallback - load default dataset
      setPosture(DEFAULT_POSTURE);
      setInventory(DEFAULT_INVENTORY);
      return DEFAULT_POSTURE;
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;

    async function initialFetch() {
      try {
        setApiError(null);

        const [postureRes, invRes, moscaRes, heatmapRes, roadmapRes] = await Promise.all([
          fetch(`${API_BASE}/api/v1/posture`),
          fetch(`${API_BASE}/api/v1/inventory`),
          fetch(`${API_BASE}/api/v1/mosca/eval`),
          fetch(`${API_BASE}/api/v1/risk`),
          fetch(`${API_BASE}/api/v1/roadmap`),
        ]);

        if (!postureRes.ok || !invRes.ok) {
          throw new Error(`Failed to load data from backend (${postureRes.status})`);
        }

        const [postureData, invData, moscaData, heatmapData, roadmapData] = await Promise.all([
          postureRes.json(),
          invRes.json(),
          moscaRes.ok ? moscaRes.json() : [],
          heatmapRes.ok ? heatmapRes.json() : [],
          roadmapRes.ok ? roadmapRes.json() : [],
        ]);

        if (!ignore) {
          setPosture(postureData);
          setInventory(invData || []);
          setMoscaPoints(moscaData || []);
          setHeatmap(Array.isArray(heatmapData) ? heatmapData : (heatmapData?.cells || []));
          setRoadmap(roadmapData || []);
          void refreshScanHistory().catch(() => setScanHistory([]));
        }
      } catch {
        if (!ignore) {
          setPosture(DEFAULT_POSTURE);
          setInventory(DEFAULT_INVENTORY);
        }
      } finally {
        if (!ignore) {
          setLoading(false);
        }
      }
    }

    initialFetch();

    return () => {
      ignore = true;
    };
  }, [refreshScanHistory]);

  // Deep-link (?id= / #results-section) hydration — syncs URL state into the Results section.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const scanId = params.get("id") || params.get("scan_id");
    if (scanId) {
      const targetId = scanId;
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActiveScanId(targetId);
      // Hydrate the Results section with this specific run's inventory (deferred to avoid sync setState in effect).
      window.setTimeout(() => {
        void loadData(true, targetId).catch(() => undefined);
      }, 0);
    }
    const hash = window.location.hash.replace(/^#/, "");
    if (hash === RESULTS_SECTION_ID || scanId) {
      setActiveSection(RESULTS_SECTION_ID);
      window.setTimeout(() => {
        document.getElementById(RESULTS_SECTION_ID)?.scrollIntoView({ behavior: "smooth" });
      }, 250);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSelectHistoricalScan(scanId: string) {
    setScanError(null);
    setActiveScanId(scanId);
    const known = scanHistory.find((row) => row.id === scanId);
    if (known) {
      setActiveScanMeta({
        id: known.id,
        target: known.target,
        target_type: known.target_type,
        environment: known.environment,
      });
    }
    // Show only the selected run's findings in the Results section.
    await loadData(true, scanId).catch(() => undefined);
    revealResults(scanId);
  }

  // --- Fetch Single Finding Detail ---
  const openFindingDrawer = async (findingId: string) => {
    setIsDrawerOpen(true);
    setDetailLoading(true);
    setFindingDetail(null);

    try {
      const runSuffix = activeScanId ? `?run_id=${encodeURIComponent(activeScanId)}` : "";
      const res = await fetch(`${API_BASE}/api/v1/findings/${encodeURIComponent(findingId)}${runSuffix}`);
      if (res.ok) {
        const data = await res.json();
        setFindingDetail(data);
      } else {
        throw new Error(`Finding details unavailable (${res.status})`);
      }
    } catch {
      setFindingDetail(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const closeDrawer = () => {
    setIsDrawerOpen(false);
    setFindingDetail(null);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // --- Scan Submission (dynamic timeout per target type) ---
  const handleStartScan = async () => {
    setScanSubmitting(true);
    setScanError(null);
    setScanSuccessMessage(null);
    const activeTimeoutMs = getScanTimeoutForTarget(scanForm.target_type, scanForm.repository);
    setScanPhaseMessage(getScanPhaseMessage(0));
    setScanElapsedMs(0);

    // Downstream payload preserves the ORIGINAL artifact: targetType +
    // targetSource + artifactMetadata + businessContext travel together.
    // Legacy flat fields (repository/artifact_id/branch) stay for compat, but
    // the scanner routes on target_type and reads the real uploaded bytes via
    // artifact_id — uploads are never filename-only.
    const payload = {
      target_type: scanForm.target_type,
      target_source: buildTargetSource(scanForm),
      artifact_metadata: buildArtifactMetadata(scanForm),
      business_context: {
        system_name: scanForm.system_name,
        owner: scanForm.owner,
        environment: scanForm.environment,
        business_criticality: scanForm.business_criticality,
        data_sensitivity: scanForm.data_sensitivity,
        internet_exposure: scanForm.internet_exposure,
        regulatory_relevance: scanForm.regulatory_relevance,
        migration_complexity: scanForm.migration_complexity,
        data_lifetime: Number(scanForm.data_lifetime),
        migration_time: Number(scanForm.migration_time),
        crqc_horizon: Number(scanForm.crqc_horizon),
      },
      repository: scanForm.repository,
      artifact_id: scanForm.artifact_id,
      branch: scanForm.target_type === "source_repo" ? scanForm.branch || "main" : "",
      environment: scanForm.environment,
      business_criticality: scanForm.business_criticality,
      system_name: scanForm.system_name,
      owner: scanForm.owner,
      data_sensitivity: scanForm.data_sensitivity,
      internet_exposure: scanForm.internet_exposure,
      regulatory_relevance: scanForm.regulatory_relevance,
      migration_complexity: scanForm.migration_complexity,
      data_lifetime: Number(scanForm.data_lifetime),
      migration_time: Number(scanForm.migration_time),
      crqc_horizon: Number(scanForm.crqc_horizon),
    };

    let scanId: string | null = null;
    let status = "RUNNING";
    let exitCode: number | undefined;
    let failureMessage: string | undefined;

    try {
      let response: Response;
      try {
        response = await fetch(`${API_BASE}/api/v1/scans`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(activeTimeoutMs),
        });
      } catch (networkError) {
        throw new Error(
          `Unable to connect to scan service at ${API_BASE}. ` +
          `Please ensure the backend is running and accessible. ` +
          (networkError instanceof Error ? `Details: ${networkError.message}` : "")
        );
      }

      let body: Record<string, unknown> | null = null;
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        body = null;
      }

      const returnedId = extractScanId(body);
      if (returnedId) scanId = returnedId;
      status = normalizeScanStatus(body?.status ?? body?.run_status) || status;
      exitCode = typeof body?.exit_code === "number" ? body.exit_code : undefined;
      failureMessage =
        typeof body?.message === "string"
          ? body.message
          : typeof body?.detail === "string"
            ? body.detail
            : Array.isArray(body?.detail)
              ? body.detail
                  .map((entry) =>
                    entry && typeof entry === "object" && "msg" in entry
                      ? String((entry as { msg: unknown }).msg)
                      : JSON.stringify(entry)
                  )
                  .join("; ")
              : undefined;

      if (!response.ok) {
        throw new Error(
          failureMessage || `Scan request failed (HTTP ${response.status}${exitCode != null ? `, exit ${exitCode}` : ""}).`
        );
      }

      if (!TERMINAL_SUCCESS.has(status) && !TERMINAL_FAILURE.has(status)) {
        setScanPolling(true);
        try {
          if (!scanId) throw new Error("Scan service returned no run ID.");
          const settled = await pollScanUntilSettled(scanId, activeTimeoutMs, (elapsed, message) => {
            setScanElapsedMs(elapsed);
            setScanPhaseMessage(message);
          });
          status = settled.status;
          exitCode = settled.exit_code ?? exitCode;
          failureMessage = settled.message ?? failureMessage;
        } finally {
          setScanPolling(false);
        }
      }

      if (TERMINAL_FAILURE.has(status) || (exitCode != null && exitCode !== 0 && !TERMINAL_SUCCESS.has(status))) {
        throw new Error(
          failureMessage ||
            `Scan failed${exitCode != null ? ` (exit code ${exitCode})` : ""} with status ${status || "FAILED"}.`
        );
      }

      if (!scanId) throw new Error("Scan service returned no run ID.");
      const finishedId: string = scanId;
      // Load only this scan's run view so the Results section reflects the just-scanned target.
      await loadData(true, finishedId);
      const finishedTarget = describeScanTarget(scanForm);
      await refreshScanHistory();
      setScanSuccessMessage("Cryptographic scan completed.");
      setActiveScanMeta({
        id: finishedId,
        target: finishedTarget,
        target_type: scanForm.target_type,
        environment: scanForm.environment,
      });
      setIsScanModalOpen(false);
      revealResults(finishedId);
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : "Scan failed. Review the target artifact and try again.";
      setScanError(message);
      const failedId: string | null = scanId;
      if (failedId) {
        void refreshScanHistory();
      }
      // Do not re-throw - error is already displayed to user via scanError state
    } finally {
      setScanSubmitting(false);
      setScanPolling(false);
      setScanPhaseMessage(null);
      setScanElapsedMs(0);
    }
  };

  // --- Mosca Calculation / Warning State ---
  const moscaViolation = useMemo(() => {
    if (!moscaPoints || moscaPoints.length === 0) return null;
    const exposed = moscaPoints.find((p) => {
      const x = p.x_data_lifetime_years ?? 0;
      const y = p.y_migration_years ?? 0;
      const z = p.z_crqc_horizon_years ?? 0;
      return x + y > z || p.urgency === "critical";
    });

    if (exposed) {
      const x = exposed.x_data_lifetime_years ?? 7;
      const y = exposed.y_migration_years ?? 4;
      const z = exposed.z_crqc_horizon_years ?? 8;
      return {
        x,
        y,
        z,
        deficit: Math.max(0, x + y - z),
        criticalCount: moscaPoints.filter((p) => p.urgency === "critical").length,
      };
    }
    return null;
  }, [moscaPoints]);

  // --- Filtered Inventory Items ---
  const filteredInventory = useMemo(() => {
    let list = inventory;

    // Filter by Heatmap Cell if selected
    if (selectedHeatmapCell) {
      if (selectedHeatmapCell.finding_ids && selectedHeatmapCell.finding_ids.length > 0) {
        list = list.filter((item) =>
          selectedHeatmapCell.finding_ids?.includes(item.finding_id)
        );
      } else {
        list = list.filter(
          (item) => item.risk_level.toLowerCase() === selectedHeatmapCell.urgency.toLowerCase()
        );
      }
    }

    // Filter by Search Query
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (item) =>
          item.algorithm_name?.toLowerCase().includes(q) ||
          item.finding_id.toLowerCase().includes(q) ||
          item.category.toLowerCase().includes(q) ||
          item.algorithm_family?.toLowerCase().includes(q)
      );
    }

    return list;
  }, [inventory, selectedHeatmapCell, search]);

  // --- Heatmap Coordinates Matrix ---
  const urgencies: Array<"critical" | "high" | "medium" | "low"> = [
    "critical",
    "high",
    "medium",
    "low",
  ];
  const criticalities: Array<"low" | "medium" | "high" | "critical"> = [
    "low",
    "medium",
    "high",
    "critical",
  ];

  if (!authReady) return null;

  if (loading) {
    return (
      <div className="flex min-h-screen w-full flex-col items-center justify-center bg-background px-6 text-foreground">
        <div className="qrypton-card flex w-full max-w-md flex-col items-center gap-6 p-8">
          <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Shield aria-hidden="true" />
          </div>
          <div className="text-center">
            <h2 className="flex items-center justify-center gap-2 text-lg font-semibold tracking-tight">
              <Loader2 className="size-4 animate-spin text-primary" aria-hidden="true" />
              Connecting to QRYPTON
            </h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Synchronizing inventory and quantum timeline posture.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen overflow-x-hidden bg-background font-sans text-foreground antialiased">
      <Sidebar active={activeSection} onNavigate={navigateTo} width={sidebarWidth} onWidthChange={setSidebarWidth} collapsed={sidebarCollapsed} onToggleCollapsed={() => setSidebarCollapsed((value) => !value)} />
      <div
        className="pl-0 transition-[padding] lg:pl-[var(--sidebar-w)]"
        style={{ "--sidebar-w": sidebarCollapsed ? "0px" : `${sidebarWidth}px` } as React.CSSProperties}
      >
      <header className="absolute right-5 top-4 z-30 flex items-center gap-3 rounded-full border border-white/10 bg-[#0b0f17]/80 px-3 py-2 backdrop-blur sm:right-8">
        <span className="grid size-8 place-items-center rounded-full bg-[#00ff87] text-xs font-black text-[#0b0f17]" aria-label="Signed-in user">Q</span>
        <button type="button" onClick={() => { window.localStorage.removeItem("qrypton.session"); window.sessionStorage.removeItem("qrypton.session"); window.localStorage.removeItem("qrypton.user"); window.sessionStorage.removeItem("qrypton.user"); router.replace("/login"); }} className="text-xs font-semibold text-white/80 hover:text-[#00ff87]">Logout</button>
      </header>
      <section className="qrypton-hero relative isolate flex min-h-[100svh] items-center overflow-hidden px-5 py-14 sm:px-10 lg:px-16">
        <div className="qrypton-hero-grid" aria-hidden="true" />
        <div className="relative z-10 mx-auto grid w-full max-w-7xl items-end gap-12 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="qrypton-hero-copy">
            <h1>QRYPTON</h1>
            <p className="qrypton-tagline">DISCOVER. ASSESS. EVOLVE.</p>
            <p className="mt-8 max-w-md text-base leading-7 text-slate-400 sm:text-lg">CRYPTOGRAPHIC DISCOVERY, QUANTUM EXPOSURE MODELLING, AND PQC MIGRATION EVIDENCE — IN ONE SECURITY CONTROL PLANE.</p>
            <button onClick={() => document.getElementById("new-scan")?.scrollIntoView({ behavior: "smooth" })} className="qrypton-scroll-cue mt-10">
              Explore your cryptographic horizon <ArrowDown className="size-4" />
            </button>
          </div>
          <div className="relative self-center justify-self-center lg:justify-self-end"><CryptoLockVisual /></div>
        </div>
      </section>

      <main className="relative mx-auto max-w-7xl space-y-8 px-4 py-16 sm:px-6 lg:px-8">
        <section id="new-scan" className="qrypton-scan-portal">
          <div><p className="qrypton-eyebrow">Start here · 02</p><h2>DISOVER. ASSES. EVOLVE.</h2><p>Map every algorithm, certificate and vulnerable dependency in your environment.</p></div>
          <button onClick={() => setIsScanModalOpen(true)} className="qrypton-plus-button" aria-label="Start a new cryptographic scan"><Plus /></button>
          <button onClick={() => setIsScanModalOpen(true)} className="qrypton-scan-label">New scan <span>→</span></button>
        </section>
        {/* Connection Error Banner if backend fails */}
        {apiError && (
          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-950/40 backdrop-blur-md flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 text-rose-300 text-sm">
              <XCircle className="h-5 w-5 text-rose-500 flex-shrink-0" />
              <span>{apiError}</span>
            </div>
            <button
              onClick={() => loadData(false)}
              className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 text-xs font-medium border border-rose-500/40 transition-colors"
            >
              Retry Connection
            </button>
          </div>
        )}

        {scanSubmitting && (
          <div className="qrypton-card flex items-center gap-3 border-primary/30 p-4" role="status" aria-live="polite">
            <Loader2 className="size-5 shrink-0 animate-spin text-primary" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold">Scan in progress</p>
              <p className="mt-0.5 text-xs text-muted-foreground">Collecting cryptographic evidence. Results open automatically when this run completes.</p>
            </div>
          </div>
        )}

        {scanError && (
          <div className="flex items-start justify-between gap-4 rounded-xl border border-rose-500/30 bg-rose-950/40 p-4" role="alert">
            <div className="flex items-start gap-3 text-sm text-rose-300">
              <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-500" />
              <div>
                <p className="font-semibold text-rose-200">Scan failed</p>
                <p className="mt-1 text-rose-300/90">{scanError}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setScanError(null)}
              className="rounded-lg border border-rose-500/40 px-3 py-1.5 text-xs font-medium text-rose-200 hover:bg-rose-500/20"
            >
              Dismiss
            </button>
          </div>
        )}

        {(!posture || posture.total_findings === 0) && (
          <section className="qrypton-card flex flex-col items-center justify-center text-center p-8 sm:p-12 space-y-4">
            <div className="flex size-14 items-center justify-center rounded-2xl bg-primary/10 text-primary border border-primary/20">
              <Shield className="size-7" aria-hidden="true" />
            </div>
            <div className="max-w-md space-y-2">
              <p className="qrypton-kicker">First-Time Assessment</p>
              <h2 className="text-2xl font-bold tracking-tight">Run First Cryptographic Scan</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Connect your repository or runtime infrastructure to discover legacy algorithms, map cryptographic evidence, and construct your post-quantum migration roadmap.
              </p>
            </div>
            <button
              onClick={() => setIsScanModalOpen(true)}
              className="inline-flex min-h-10 items-center justify-center rounded-xl bg-primary px-6 text-sm font-semibold text-primary-foreground shadow-md transition-all hover:opacity-90 active:scale-95"
            >
              Run First Cryptographic Scan
            </button>
          </section>
        )}

        <section aria-labelledby="attention-heading" className="qrypton-card overflow-hidden">
          <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="qrypton-kicker">Operational priority</p>
              <h2 id="attention-heading" className="mt-1 text-xl font-semibold tracking-tight">What needs attention?</h2>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">Start with the highest-impact exposure and use the evidence drawer to assign the next action.</p>
            </div>
            <button onClick={() => document.getElementById("inventory")?.scrollIntoView({ behavior: "smooth" })} className="inline-flex min-h-9 items-center justify-center rounded-md border border-border px-3 text-sm font-semibold text-foreground transition-colors hover:bg-muted">Review inventory <ChevronRight data-icon="inline-end" /></button>
          </div>
          <div className="grid gap-0 divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <div className="flex items-start gap-3 p-5"><div className="rounded-md bg-red-50 p-2 text-red-700"><AlertTriangle className="size-4" aria-hidden="true" /></div><div><p className="text-2xl font-semibold tabular-nums">{posture?.critical_findings_count ?? 0}</p><p className="text-sm font-medium">Critical findings</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Prioritize remediation before the next review.</p></div></div>
            <div className="flex items-start gap-3 p-5"><div className="rounded-md bg-amber-50 p-2 text-amber-700"><ShieldAlert className="size-4" aria-hidden="true" /></div><div><p className="text-2xl font-semibold tabular-nums">{moscaViolation ? `${moscaViolation.deficit.toFixed(1)}y` : "—"}</p><p className="text-sm font-medium">Mosca deficit</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{moscaViolation ? "Migration effort exceeds the security horizon." : "No timeline deficit currently detected."}</p></div></div>
            <div className="flex items-start gap-3 p-5"><div className="rounded-md bg-blue-50 p-2 text-primary"><Search className="size-4" aria-hidden="true" /></div><div><p className="text-2xl font-semibold tabular-nums">{posture?.unique_asset_ids ?? 0}</p><p className="text-sm font-medium">Assets to validate</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Open the inventory to inspect evidence and ownership.</p></div></div>
          </div>
        </section>

        <ScanHistory
          scans={scanHistory}
          onSelectScan={(scanId) => {
            void handleSelectHistoricalScan(scanId);
          }}
          onDelete={(scanId) => { void deleteHistoricalScan(scanId); }}
        />

        {/* --- Top KPI Cards --- */}
        <section id="dashboard" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              Executive Cryptographic Posture
            </h2>
            {posture?.run_status && (
              <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                Status: {posture.run_status.toUpperCase()}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Total Findings */}
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-mono uppercase tracking-wider">Total Findings</span>
                <div className="p-2 rounded-lg bg-slate-800/60 text-cyan-400">
                  <FileText className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-mono font-bold text-white">
                  {posture?.total_findings ?? 0}
                </span>
                <span className="text-xs text-slate-400 font-mono">Discovered Assets</span>
              </div>
            </div>

            {/* 2. Critical & High Counts */}
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-mono uppercase tracking-wider">
                  Critical / High Risk
                </span>
                <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <AlertTriangle className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-mono font-bold text-rose-500">
                  {posture?.critical_findings_count ?? 0}
                </span>
                <span className="text-xl font-mono font-semibold text-amber-500">
                  / {posture?.high_findings_count ?? 0}
                </span>
                <span className="ml-auto text-xs text-slate-400 font-mono">Immediate Action</span>
              </div>
            </div>

            {/* 3. Scanned Assets */}
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-mono uppercase tracking-wider">Scanned Assets</span>
                <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  <Shield className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-mono font-bold text-white">
                  {posture?.unique_asset_ids ?? 0}
                </span>
                <span className="text-xs text-slate-400 font-mono">Inventories Tracked</span>
              </div>
            </div>

            {/* 4. Policy Status */}
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-mono uppercase tracking-wider">Policy Compliance</span>
                {posture?.policy_passed ? (
                  <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <CheckCircle2 className="h-4 w-4" />
                  </div>
                ) : (
                  <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    <ShieldAlert className="h-4 w-4" />
                  </div>
                )}
              </div>
              <div className="flex flex-col">
                {posture?.policy_passed ? (
                  <span className="text-2xl font-mono font-bold text-emerald-400">
                    PASSED
                  </span>
                ) : (
                  <div>
                    <span className="text-2xl font-mono font-bold text-rose-500">
                      VIOLATIONS
                    </span>
                    <span className="text-xs text-rose-400/80 font-mono block truncate">
                      {posture?.policy_violations?.length || 0} non-compliant findings
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <RiskPrioritization
          heatmap={heatmap}
          inventory={inventory}
          selected={selectedHeatmapCell}
          onFilter={setSelectedHeatmapCell}
          onSelect={openFindingDrawer}
        />

        {/* --- Legacy Dual Command Grid (Heatmap + Roadmap) --- */}
        <div className="hidden grid-cols-1 gap-8 lg:grid lg:grid-cols-12">
          {/* Left: 4x4 Risk Heatmap */}
          <section
            id="heatmap"
            className="lg:col-span-6 rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div>
                  <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    4x4 Risk Matrix (Mosca Urgency vs Criticality)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Click any cell to filter the inventory table below
                  </p>
                </div>
                {selectedHeatmapCell && (
                  <button
                    onClick={() => setSelectedHeatmapCell(null)}
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 bg-cyan-950/60 px-2.5 py-1 rounded-lg border border-cyan-800"
                  >
                    Clear Filter
                    <X className="h-3 w-3" />
                  </button>
                )}
              </div>

              {/* Heatmap Grid */}
              <div className="mt-6">
                <div className="grid grid-cols-5 gap-2 text-center text-xs font-mono">
                  {/* Top Header Corner */}
                  <div className="text-[10px] text-slate-500 uppercase flex items-center justify-center font-bold">
                    Urgency \ Crit
                  </div>
                  {criticalities.map((crit) => (
                    <div
                      key={crit}
                      className="text-[11px] font-semibold text-slate-400 uppercase py-1"
                    >
                      {crit}
                    </div>
                  ))}

                  {/* 4 Rows */}
                  {urgencies.map((urgency) => (
                    <React.Fragment key={urgency}>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase flex items-center justify-end pr-2">
                        {urgency}
                      </div>
                      {criticalities.map((crit) => {
                        const cellData = heatmap.find(
                          (c) =>
                            c.mosca_urgency?.toLowerCase() === urgency.toLowerCase() &&
                            c.business_criticality?.toLowerCase() === crit.toLowerCase()
                        );
                        const count = cellData?.finding_count ?? 0;
                        const isSelected =
                          selectedHeatmapCell?.urgency === urgency &&
                          selectedHeatmapCell?.criticality === crit;

                        // Dynamic cell color mapping
                        let cellStyle = "bg-slate-950/70 border-slate-800/80 text-slate-600";
                        if (count > 0) {
                          if (urgency === "critical") {
                            cellStyle =
                              "bg-rose-950/60 border-rose-500/50 text-rose-300 hover:bg-rose-900/60 shadow-lg shadow-rose-950/40";
                          } else if (urgency === "high") {
                            cellStyle =
                              "bg-amber-950/60 border-amber-500/50 text-amber-300 hover:bg-amber-900/60 shadow-lg shadow-amber-950/40";
                          } else if (urgency === "medium") {
                            cellStyle =
                              "bg-blue-950/60 border-blue-500/50 text-blue-300 hover:bg-blue-900/60";
                          } else {
                            cellStyle =
                              "bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800";
                          }
                        }

                        if (isSelected) {
                          cellStyle += " ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-950";
                        }

                        return (
                          <button
                            key={`${urgency}-${crit}`}
                            onClick={() => {
                              if (isSelected) {
                                setSelectedHeatmapCell(null);
                              } else {
                                setSelectedHeatmapCell({
                                  urgency,
                                  criticality: crit,
                                  finding_ids: cellData?.finding_ids,
                                });
                              }
                            }}
                            className={`h-14 rounded-xl border flex flex-col items-center justify-center transition-all cursor-pointer ${cellStyle}`}
                          >
                            <span className="text-base font-bold font-mono">{count}</span>
                            <span className="text-[9px] opacity-70">
                              {count === 1 ? "finding" : "findings"}
                            </span>
                          </button>
                        );
                      })}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
              <span>Y-Axis: Mosca Urgency (Time Horizon)</span>
              <span>X-Axis: Asset Business Impact</span>
            </div>
          </section>

          {/* Right: PQC Migration Roadmap */}
          <section
            id="roadmap"
            className="lg:col-span-6 rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-md flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-cyan-400" />
                  PQC Migration Roadmap (NIST FIPS Remediation Queue)
                </h3>
                <span className="text-xs font-mono text-slate-400">
                  {roadmap.length} queued action items
                </span>
              </div>

              <div className="mt-4 space-y-3 max-h-[300px] overflow-y-auto pr-1">
                {roadmap.length > 0 ? (
                  roadmap.map((item, idx) => (
                    <div
                      key={`${item.finding_id || 'item'}-${idx}`}
                      className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 hover:border-slate-700 transition-all flex flex-col gap-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            PRIORITY {item.priority}
                          </span>
                          {item.hybrid_mode && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                              HYBRID: {item.hybrid_mode}
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] font-mono text-slate-400 truncate max-w-[140px]">
                          {item.finding_id}
                        </span>
                      </div>

                      <p className="text-xs text-slate-200 font-medium leading-snug">
                        {item.action}
                      </p>

                      {/* Target Algorithms / Standards tags */}
                              {item.target_algorithms && item.target_algorithms.length > 0 && (
                                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                                  <span className="text-[10px] text-slate-400 font-mono">Target:</span>
                                  {item.target_algorithms.map((algo, i) => (
                                    <span
                                      key={`${algo || 'item'}-${i}`}
                                      className="px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                    >
                                      {algo}
                                    </span>
                                  ))}
                                </div>
                              )}
                    </div>
                  ))
                ) : (
                  <div className="py-12 text-center text-slate-500 text-xs font-mono space-y-3">
                    <p>No PQC migration actions queued yet.</p>
                    <button
                      onClick={() => setIsScanModalOpen(true)}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs"
                    >
                      Run New Scan to Generate Roadmap
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Standard: NIST FIPS 203 (ML-KEM) &amp; FIPS 204 (ML-DSA)</span>
            </div>
          </section>
        </div>

        <section id={RESULTS_SECTION_ID} aria-labelledby="results-heading" className="space-y-3 scroll-mt-24">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="qrypton-kicker">Scan results</p>
              <h2 id="results-heading" className="mt-1 text-xl font-semibold tracking-tight">Results</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {activeScanMeta
                  ? `Showing only findings for “${activeScanMeta.target}” (${activeScanMeta.id}).`
                  : activeScanId
                    ? `Showing inventory and findings for ${activeScanId}.`
                    : "Inventory, evidence, and risk from the latest completed scan. Run a scan to see its dedicated result here."}
              </p>
              {activeScanMeta && (
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                  <span className="inline-flex items-center rounded-full border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono font-semibold text-primary">
                    {activeScanMeta.id}
                  </span>
                  {activeScanMeta.target_type && (
                    <span className="inline-flex items-center rounded-full border border-border px-2.5 py-1 font-mono text-muted-foreground">
                      {activeScanMeta.target_type}
                    </span>
                  )}
                  <span className="inline-flex items-center rounded-full border border-border px-2.5 py-1 font-mono capitalize text-muted-foreground">
                    {activeScanMeta.environment}
                  </span>
                  <span className="inline-flex items-center rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-semibold text-emerald-300">
                    {posture?.total_findings ?? 0} findings
                  </span>
                </div>
              )}
            </div>
            {activeScanId && (
              <button
                type="button"
                onClick={() => {
                  setActiveScanId(null);
                  setActiveScanMeta(null);
                  void loadData(true, null);
                }}
                className="text-xs font-semibold text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
              >
                Show latest scan instead
              </button>
            )}
          </div>
          {activeScanId && inventory.length === 0 ? (
            <div className="qrypton-card p-8 text-center" role="status">
              <p className="text-sm font-semibold">No findings stored for this scan yet.</p>
              <p className="mt-1 text-xs text-muted-foreground">
                The run {activeScanId} completed but returned an empty inventory. Try another target or re-run the scan.
              </p>
            </div>
          ) : (
            <CryptoInventory items={filteredInventory} query={search} onQueryChange={setSearch} onSelect={openFindingDrawer} onClear={() => { setSearch(""); setSelectedHeatmapCell(null); }} />
          )}
        </section>

        <section id="reports" className="grid gap-4 lg:grid-cols-2" aria-labelledby="reports-heading">
          <div className="qrypton-card p-6"><p className="qrypton-kicker">Export engine</p><h2 id="reports-heading" className="mt-1 text-xl font-semibold">Reports &amp; CBOM</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Export CycloneDX-compatible CBOM JSON, a printable executive PDF summary, or a provenance-preserving HTML audit report from Scan History or the inventory.</p><div className="mt-4 flex flex-wrap gap-2"><button onClick={() => document.getElementById("scans")?.scrollIntoView({ behavior: "smooth" })} className="rounded-md bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">Open scan exports</button><button onClick={() => document.getElementById("inventory")?.scrollIntoView({ behavior: "smooth" })} className="rounded-md border border-border px-3 py-2 text-sm font-semibold">Export inventory CBOM</button></div></div>
          <div className="qrypton-card p-6"><p className="qrypton-kicker">CI/CD delta</p><h2 className="mt-1 text-xl font-semibold">Scan comparison</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Compare two historical runs of the same target to review new and removed assets, changed algorithms or key sizes, newly critical risks, resolved findings, and overall risk movement.</p><div className="mt-4 grid grid-cols-2 gap-2 text-xs"><span className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2">+ New crypto assets</span><span className="rounded border border-rose-500/30 bg-rose-500/10 p-2">New critical risks</span><span className="rounded border border-border p-2">Changed parameters</span><span className="rounded border border-border p-2">Resolved findings</span></div></div>
        </section>

        <section id="integrations" className="qrypton-card p-6" aria-labelledby="integrations-heading"><p className="qrypton-kicker">Controlled connections</p><h2 id="integrations-heading" className="mt-1 text-xl font-semibold">Integrations</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">Connect source control, CI/CD, container registries, and cloud KMS through organization-managed credentials. New scans never collect secrets in the workflow.</p><div className="mt-4 flex flex-wrap gap-2 text-xs"><span className="rounded-full border border-border px-3 py-1.5">Source control</span><span className="rounded-full border border-border px-3 py-1.5">Container registry</span><span className="rounded-full border border-border px-3 py-1.5">Cloud KMS</span><span className="rounded-full border border-border px-3 py-1.5">CI/CD</span></div></section>

        {/* Live Cryptographic Network Scanner at bottom of dashboard (Task 6) */}
        {inventory.length > 0 ? <LiveTelemetry /> : <section id="live-scanner" className="qrypton-card qrypton-empty-inspection"><p className="qrypton-eyebrow">Network inspection</p><h2>See your result stream here.</h2><p>Live handshakes, classification activity, and exposure signals appear after your first scan connects an asset.</p><button onClick={() => setIsScanModalOpen(true)}>Configure a scan <ArrowDown className="size-4" /></button></section>}
      </main>
      </div>

      <FindingDetail
        open={isDrawerOpen}
        loading={detailLoading}
        detail={findingDetail}
        onClose={closeDrawer}
        copiedId={copiedId}
        onCopy={copyToClipboard}
      />

      <ScanWorkflow
        open={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        form={scanForm}
        setForm={setScanForm}
        onSubmit={handleStartScan}
        submitting={scanSubmitting}
        successMessage={scanSuccessMessage}
        submitError={scanError}
        polling={scanPolling}
        phaseMessage={scanPhaseMessage}
        elapsedMs={scanElapsedMs}
      />

    </div>
  );
}
