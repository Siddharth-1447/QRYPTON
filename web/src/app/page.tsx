"use client";

import { GlossaryText } from "@/components/glossary";
import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ScanWorkflow, DEFAULT_SCAN_FORM, describeScanTarget, buildTargetSource, buildArtifactMetadata, type ScanForm } from "@/components/scan-workflow";
import { ScanNotifications, trackScan } from "@/components/scan-notifications";
import type { ScanStatus } from "@/lib/scan-polling";
import { clearScanTarget } from "@/lib/scan-form";
import { sectionAtScrollPosition } from "@/lib/section-navigation";
import { API_BASE } from "@/lib/api";
import { downloadScanReports } from "@/lib/scan-download";
import { inFlight } from "@/lib/in-flight";
import { getScanPhaseMessage, normalizeScanStatus, pollScanUntilSettled, TERMINAL_SUCCESS, TERMINAL_FAILURE } from "@/lib/scan-polling";
import { useInventoryView } from "@/lib/use-inventory-view";
import { writeInventoryView } from "@/lib/inventory-view";
import type { CryptoInventoryRow } from "@/lib/inventory-view";
import { CryptoInventory } from "@/components/crypto-inventory";
import { FindingDetail, type FindingDetailData, type FindingRoadmapItem } from "@/components/finding-detail";
import { ScanExport } from "@/components/scan-export";
import { RiskPrioritization } from "@/components/risk-prioritization";
import { LiveTelemetry } from "@/components/live-telemetry";
import { NETWORK_SAMPLE_MODE } from "@/lib/network-sample";
import { ScanComparison } from "@/components/scan-comparison";
import { RoleHome } from "@/components/productivity";
import { ScanHistory, DEFAULT_SCANS, type ScanHistoryRecord } from "@/components/scan-history";
import { Sidebar, NAV_SECTIONS, SIDEBAR_DEFAULT_WIDTH } from "@/components/sidebar";
import { Logo } from "@/components/logo";
import { HeroLogo } from "@/components/hero-logo";
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Search,
  Loader2,
  XCircle,
  CheckCircle2,
  Layers,
  ChevronRight,
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
  unknown_findings_count: number;
  unassessed_findings_count: number;
  run_status: string;
  scanner_failed_count: number;
  scanner_partial_count: number;
  policy_passed: boolean;
  policy_violations: string[];
}

type InventoryRow = CryptoInventoryRow;

interface RiskHeatmapCell {
  mosca_urgency: "critical" | "high" | "medium" | "low" | "not_applicable" | "unknown";
  business_criticality: "critical" | "high" | "medium" | "low" | "unclassified";
  finding_count: number;
  finding_ids: string[];
}

interface MoscaPoint {
  finding_id: string;
  urgency: "critical" | "high" | "medium" | "low" | "not_applicable" | "unknown";
  mosca_applicable: "yes" | "no" | "unknown";
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

const RESULTS_SECTION_ID = "results-section";
const SCANS_PER_PAGE = 5;
const DASHBOARD_REQUEST_TIMEOUT_MS = 20_000;

function fetchDashboardSnapshot(runId?: string | null) {
  return inFlight(`dashboard:${runId ?? ""}`, () => requestDashboardSnapshot(runId));
}

async function requestDashboardSnapshot(runId?: string | null) {
  const suffix = runId ? `?run_id=${encodeURIComponent(runId)}` : "";
  const response = await fetch(`${API_BASE}/api/v1/dashboard${suffix}`, {
    signal: AbortSignal.timeout(DASHBOARD_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Dashboard endpoint failed (${response.status}).`);
  const snapshot = await response.json() as Record<string, unknown>;
  const { posture, inventory, mosca, heatmap: cells, roadmap } = snapshot;
  if (!Array.isArray(inventory) || !Array.isArray(mosca) || !Array.isArray(roadmap)) {
    throw new Error("Dashboard endpoint returned an invalid collection.");
  }
  if (!Array.isArray(cells) || !posture || typeof posture !== "object") {
    throw new Error("Dashboard endpoint returned an invalid posture or risk matrix.");
  }

  const findings = inventory as InventoryRow[];
  const points = mosca as MoscaPoint[];
  const heatmap = cells as RiskHeatmapCell[];
  const urgencyDimensions = new Set(["critical", "high", "medium", "low", "not_applicable", "unknown"]);
  const criticalityDimensions = new Set(["low", "medium", "high", "critical", "unclassified"]);
  const heatmapKeys = new Set(heatmap.map((cell) => `${cell.mosca_urgency}:${cell.business_criticality}`));
  const findingIds = new Set(findings.map((finding) => finding.finding_id));
  const heatmapIds = heatmap.flatMap((cell) => cell.finding_ids ?? []);
  const moscaIds = points.map((point) => point.finding_id);
  const postureData = posture as ExecutivePosture;
  const postureTotal = postureData.critical_findings_count + postureData.high_findings_count
    + postureData.medium_findings_count + postureData.low_findings_count
    + postureData.informational_findings_count + postureData.unknown_findings_count
    + postureData.unassessed_findings_count;
  const sameIds = (ids: string[]) => ids.length === findingIds.size
    && new Set(ids).size === findingIds.size
    && ids.every((id) => findingIds.has(id));
  if (
    findingIds.size !== findings.length
    || postureData.total_findings !== findings.length
    || postureTotal !== findings.length
    || heatmap.length !== urgencyDimensions.size * criticalityDimensions.size
    || heatmapKeys.size !== heatmap.length
    || heatmap.some((cell) => (
      !urgencyDimensions.has(cell.mosca_urgency)
      || !criticalityDimensions.has(cell.business_criticality)
      || cell.finding_count !== cell.finding_ids.length
    ))
    || !sameIds(heatmapIds)
    || !sameIds(moscaIds)
    || (roadmap as RoadmapRow[]).some((row) => !findingIds.has(row.finding_id))
  ) {
    throw new Error("Dashboard endpoints do not reconcile to one persisted finding set.");
  }
  return {
    posture: postureData,
    inventory: findings,
    mosca: points,
    heatmap,
    roadmap: roadmap as RoadmapRow[],
  };
}

function extractScanId(payload: Record<string, unknown> | null | undefined): string | null {
  if (!payload) return null;
  for (const key of ["scan_id", "run_id", "id"]) {
    const value = payload[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function nameFromLogin(identity: string): string {
  const source = identity.includes("@") ? identity.split("@")[0] : identity;
  if (!source || source.includes(":")) return "Viewer";
  return source.replace(/[._-]+/g, " ").trim().split(/\s+/).filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1)).join(" ") || "Viewer";
}

export default function QryptonCommandCenter() {
  const router = useRouter();
  // --- Data State ---
  const [posture, setPosture] = useState<ExecutivePosture | null>(null);
  const [inventory, setInventory] = useState<InventoryRow[]>([]);
  const [moscaPoints, setMoscaPoints] = useState<MoscaPoint[]>([]);
  const [heatmap, setHeatmap] = useState<RiskHeatmapCell[]>([]);
  const [roadmap, setRoadmap] = useState<RoadmapRow[]>([]);

  const [loading, setLoading] = useState<boolean>(true);
  const [authReady, setAuthReady] = useState<boolean>(false);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const displayedRunId = useRef<string | null>(null);
  const snapshotRequestId = useRef(0);

  const [sidebarWidth, setSidebarWidth] = useState(SIDEBAR_DEFAULT_WIDTH);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("dashboard");
  const [loggedInUser, setLoggedInUser] = useState<string>("");
  useEffect(() => {
    queueMicrotask(() => setLoggedInUser(nameFromLogin(
      window.localStorage.getItem("qrypton.email") ||
      window.sessionStorage.getItem("qrypton.email") ||
      window.localStorage.getItem("qrypton.user") ||
      window.sessionStorage.getItem("qrypton.user") ||
      "Viewer"
    )));
  }, []);


  useEffect(() => {
    const sessionActive = window.localStorage.getItem("qrypton.session") === "active" || window.sessionStorage.getItem("qrypton.session") === "active";
    if (sessionActive) {
      queueMicrotask(() => setAuthReady(true));
    } else {
      router.replace("/login");
    }
  }, [router]);

  useEffect(() => {
    if (!authReady) return;
    let frame = 0;
    const update = () => {
      frame = 0;
      const positions = NAV_SECTIONS.flatMap(({ id }) => {
        const element = document.getElementById(id);
        return element ? [{ id, top: element.getBoundingClientRect().top }] : [];
      });
      setActiveSection(sectionAtScrollPosition(positions, 120,
        window.scrollY > 0 && window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2));
    };
    const schedule = () => { if (!frame) frame = window.requestAnimationFrame(update); };
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    const observer = new ResizeObserver(schedule);
    observer.observe(document.body);
    schedule();
    return () => {
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      observer.disconnect();
      window.cancelAnimationFrame(frame);
    };
  }, [authReady]);

  const navigateTo = useCallback((id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: "instant" });
  }, []);

  const [scanProgress, setScanProgress] = useState<ScanStatus | null>(null);
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
  const detailRequest = useRef(0);
  const [findingDetail, setFindingDetail] = useState<FindingDetailData | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // --- Scan Modal State ---
  const [isScanModalOpen, setIsScanModalOpen] = useState<boolean>(false);
  const [scanSubmitting, setScanSubmitting] = useState<boolean>(false);
  const [scanSuccessMessage, setScanSuccessMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [completedScanId, setCompletedScanId] = useState<string | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>(DEFAULT_SCANS);
  const [scanHistoryPage, setScanHistoryPage] = useState(0);
  const [scanHistoryTotal, setScanHistoryTotal] = useState(0);
  const [sampleLoading, setSampleLoading] = useState(false);

  const [scanForm, setScanForm] = useState<ScanForm>(DEFAULT_SCAN_FORM);
  const [inventoryView, updateInventoryView] = useInventoryView(activeScanId);
  const selectedHeatmapCell = useMemo(() => {
    if (!inventoryView.urgency) return null;
    const cells = heatmap.filter((item) => item.mosca_urgency === inventoryView.urgency && (!inventoryView.criticality || item.business_criticality === inventoryView.criticality));
    return cells.length ? { urgency: inventoryView.urgency, criticality: inventoryView.criticality, finding_ids: cells.flatMap(cell => cell.finding_ids) } : null;
  }, [heatmap, inventoryView.urgency, inventoryView.criticality]);


  const resetScanOutcome = () => {
    setScanProgress(null);
    setScanError(null);
    setScanSuccessMessage(null);
    setCompletedScanId(null);
    setScanPhaseMessage(null);
    setScanElapsedMs(0);
  };
  const openScan = () => {
    if (!scanSubmitting && !scanPolling) resetScanOutcome();
    setIsScanModalOpen(true);
  };

  const refreshScanHistory = useCallback(async (page = 0) => {
    const response = await fetch(
      `${API_BASE}/api/v1/scans?limit=${SCANS_PER_PAGE}&offset=${page * SCANS_PER_PAGE}`,
      { signal: AbortSignal.timeout(DASHBOARD_REQUEST_TIMEOUT_MS) },
    );
    if (!response.ok) throw new Error("Unable to load persisted scan history.");
    const rows = await response.json() as Array<Record<string, unknown>>;
    const records = rows.map((row) => ({
      id: String(row.scan_id ?? row.run_id ?? ""),
      timestamp: String(row.completed_at ?? row.started_at ?? ""),
      target: String(row.artifact ?? "unavailable"),
      target_type: String(row.target_type ?? "unknown"),
      environment: String(row.environment ?? "unknown"),
      criticalCount: Number(row.critical_findings_count ?? 0),
      highCount: Number(row.high_findings_count ?? 0),
      mediumCount: Number(row.medium_findings_count ?? 0),
      totalFindings: Number(row.total_findings ?? 0),
      status: (["PENDING", "QUEUED"].includes(normalizeScanStatus(row.status)) ? "RUNNING" : normalizeScanStatus(row.status)) as ScanHistoryRecord["status"],
      sampleData: row.sample_data === true,
    })).filter((row) => row.id);
    setScanHistory(records);
    setScanHistoryPage(page);
    setScanHistoryTotal(Number(response.headers.get("X-Total-Count") ?? records.length));
    return records;
  }, []);

  const onBackgroundScanSettled = useCallback(() => {
    void refreshScanHistory(0).catch(() => {});
  }, [refreshScanHistory]);

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
    await refreshScanHistory(scanHistoryPage);
  }, [activeScanId, refreshScanHistory, scanHistoryPage]);

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
      document.getElementById(RESULTS_SECTION_ID)?.scrollIntoView({ behavior: "instant", block: "start" });
    });
  }, []);

  // --- Data Fetching (per-scan when runId is provided) ---
  const loadData = useCallback(async (isSilent = false, runId?: string | null) => {
    const requestId = ++snapshotRequestId.current;
    // A refresh of the displayed run keeps the last complete snapshot in place.
    // A different run must clear it so two immutable scans cannot be mixed.
    const switchingRun = !isSilent || runId !== displayedRunId.current;
    if (switchingRun) {
      setPosture(null);
      setInventory([]);
      setMoscaPoints([]);
      setHeatmap([]);
      setRoadmap([]);
      displayedRunId.current = null;
    }
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);
      setApiError(null);

      const snapshot = await fetchDashboardSnapshot(runId);
      if (requestId !== snapshotRequestId.current) return;
      setPosture(snapshot.posture);
      setInventory(snapshot.inventory);
      setMoscaPoints(snapshot.mosca);
      setHeatmap(snapshot.heatmap);
      setRoadmap(snapshot.roadmap);
      displayedRunId.current = runId ?? null;
      return snapshot.posture;
    } catch {
      if (requestId !== snapshotRequestId.current) return;
      if (switchingRun) {
        setPosture(null);
        setInventory([]);
        setMoscaPoints([]);
        setHeatmap([]);
        setRoadmap([]);
      }
      setApiError(switchingRun
        ? "Backend assessment data is unavailable. Dashboard metrics are withheld until canonical results load."
        : "Refresh failed. The last loaded Scan remains visible; retry to check for updates.");
    } finally {
      if (requestId === snapshotRequestId.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  const loadSampleWorkspace = async () => {
    setSampleLoading(true);
    setApiError(null);
    try {
      const response = await fetch(`${API_BASE}/api/v1/sample-workspace`, { method: "POST" });
      if (!response.ok) throw new Error("Sample workspace could not be loaded. Retry after checking the backend.");
      const result = await response.json() as { run_id: string };
      await refreshScanHistory(0);
      await loadData(true, result.run_id);
      setActiveScanId(result.run_id);
      setActiveScanMeta({ id: result.run_id, target: "Sample payment app (synthetic)", target_type: "source_repo", environment: "production" });
      revealResults(result.run_id);
    } catch (cause) {
      setApiError(cause instanceof Error ? cause.message : "Sample workspace could not be loaded.");
    } finally {
      setSampleLoading(false);
    }
  };

  const removeSampleWorkspace = async () => {
    if (!window.confirm("Remove both sample scans? Real scans will be kept.")) return;
    setSampleLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/v1/sample-workspace`, { method: "DELETE" });
      if (!response.ok) throw new Error("Sample data could not be removed.");
      window.location.reload();
    } catch (cause) {
      setApiError(cause instanceof Error ? cause.message : "Sample data could not be removed.");
      setSampleLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;

    async function initialFetch() {
      try {
        setApiError(null);

        // Deep-link (?id=) mounts load that specific run via the effect below.
        const params = new URLSearchParams(window.location.search);
        const deepId = params.get("id") || params.get("scan_id");
        const history = await refreshScanHistory();
        if (!deepId) {
          const selectedRun = history.find((scan) => scan.status === "COMPLETED" || scan.status === "PARTIAL");
          if (!selectedRun) return;
          const snapshot = await fetchDashboardSnapshot(selectedRun.id);

          if (!ignore) {
            setPosture(snapshot.posture);
            setInventory(snapshot.inventory);
            setMoscaPoints(snapshot.mosca);
            setHeatmap(snapshot.heatmap);
            setRoadmap(snapshot.roadmap);
            displayedRunId.current = selectedRun.id;
            setActiveScanId(selectedRun.id);
            setActiveScanMeta({
              id: selectedRun.id,
              target: selectedRun.target,
              target_type: selectedRun.target_type,
              environment: selectedRun.environment,
            });
          }
        }
      } catch {
        if (!ignore) {
          setPosture(null);
          setInventory([]);
          setMoscaPoints([]);
          setHeatmap([]);
          setRoadmap([]);
          setApiError("Backend assessment data is unavailable. Dashboard metrics are withheld until canonical results load.");
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
        document.getElementById(RESULTS_SECTION_ID)?.scrollIntoView({ behavior: "instant" });
      }, 250);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSelectHistoricalScan(scanId: string) {
    const expectedRequestId = snapshotRequestId.current + 1;
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
    if (snapshotRequestId.current === expectedRequestId) revealResults(scanId);
  }

  // --- Fetch Single Finding Detail ---
  const openFindingDrawer = async (findingId: string) => {
    const requestVersion = ++detailRequest.current;
    setIsDrawerOpen(true);
    setDetailLoading(true);
    setFindingDetail(null);

    try {
      const runSuffix = activeScanId ? `?run_id=${encodeURIComponent(activeScanId)}` : "";
      const res = await fetch(`${API_BASE}/api/v1/findings/${encodeURIComponent(findingId)}${runSuffix}`, { signal: AbortSignal.timeout(10000) });
      if (res.ok) {
        const data = await res.json();
        if (requestVersion !== detailRequest.current) return;
        setFindingDetail(data);
      } else {
        throw new Error(`Finding details unavailable (${res.status})`);
      }
    } catch {
      if (requestVersion === detailRequest.current) setFindingDetail(null);
    } finally {
      if (requestVersion === detailRequest.current) setDetailLoading(false);
    }
  };

  const closeDrawer = useCallback(() => {
    detailRequest.current += 1;
    setIsDrawerOpen(false);
    setFindingDetail(null);
  }, []);

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
    setCompletedScanId(null);
    // Section 3: clear stale results immediately so a prior run is never
    // visible while the new scan is queued/polling. Fresh data lands via
    // loadData(finishedId) on success; failures stay visibly empty.
    setPosture(null);
    setInventory([]);
    setMoscaPoints([]);
    setHeatmap([]);
    setRoadmap([]);
    setActiveScanId(null);
    setActiveScanMeta(null);
    setFindingDetail(null);
    setIsDrawerOpen(false);
    setScanProgress(null);
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
        data_lifetime: scanForm.data_lifetime,
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
      data_lifetime: scanForm.data_lifetime,
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
          // Queue-accept is fast (resolve + shape check only), 10s is plenty for server request receipt.
          signal: AbortSignal.timeout(10_000),
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

      if (scanId) { trackScan(scanId); void refreshScanHistory(0).catch(() => {}); }
      if (!TERMINAL_SUCCESS.has(status) && !TERMINAL_FAILURE.has(status)) {
        setScanPolling(true);
        try {
          if (!scanId) throw new Error("Scan service returned no run ID.");
          const settled = await pollScanUntilSettled(API_BASE, scanId, (elapsed, message, snapshot) => {
            if (snapshot) setScanProgress(snapshot);
            setScanElapsedMs(elapsed);
            setScanPhaseMessage(message);
          });
          if (!settled.pollingError) setScanProgress(settled);
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
      const finishedTarget = describeScanTarget(scanForm);
      const downloadMessage = await downloadScanReports(finishedId, scanForm.report_download ?? "none");
      // Completion consumes the target even if loading its dashboard later fails.
      setScanForm((current) => clearScanTarget(current));
      // Load only this scan's run view so the Results section reflects the just-scanned target.
      await loadData(true, finishedId);
      await refreshScanHistory(0);
      setScanSuccessMessage(`${status === "PARTIAL" ? "Scan completed with warnings." : "Cryptographic scan completed."} ${downloadMessage}`.trim());
      setActiveScanMeta({
        id: finishedId,
        target: finishedTarget,
        target_type: scanForm.target_type,
        environment: scanForm.environment,
      });
      setActiveScanId(finishedId);
      // Keep the workflow open on completion: the prominent "Show Results"
      // button takes the user to the Results section on demand instead of
      // auto-scrolling or quietly rendering the inventory.
      setCompletedScanId(finishedId);
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : "Scan failed. Review the target artifact and try again.";
      setScanError(message);
      const failedId: string | null = scanId;
      if (failedId) {
        void refreshScanHistory(0);
      }
      // Do not re-throw - error is already displayed to user via scanError state
    } finally {
      setScanSubmitting(false);
      setScanPolling(false);
      setScanPhaseMessage(null);
      setScanElapsedMs(0);
    }
  };

  // Per-finding persisted outcomes stay separate; never infer a global Mosca tier.
  const moscaDistribution = useMemo(() => {
    const tiers: MoscaPoint["urgency"][] = ["critical", "high", "medium", "low", "not_applicable", "unknown"];
    return Object.fromEntries(tiers.map((tier) => [tier, moscaPoints.filter((point) => point.urgency === tier).length])) as Record<MoscaPoint["urgency"], number>;
  }, [moscaPoints]);

  useEffect(() => {
    const refresh = () => { void fetchDashboardSnapshot(activeScanId).then(data => { setInventory(data.inventory); setRoadmap(data.roadmap); }).catch(() => {}); };
    window.addEventListener("qrypton:status-changed", refresh);
    return () => window.removeEventListener("qrypton:status-changed", refresh);
  }, [activeScanId]);

  const refreshInvestigation = async () => {
    const snapshot = await fetchDashboardSnapshot(activeScanId);
    setInventory(snapshot.inventory);
    setRoadmap(snapshot.roadmap);
  };

  const latestDashboardScan = scanHistory.find(
    (scan) => scan.status === "COMPLETED" || scan.status === "PARTIAL",
  );
  const activeScan = scanHistory.find((scan) => scan.id === activeScanId);
  const activeSample = activeScan?.sampleData === true;
  const sampleScans = scanHistory.filter((scan) => scan.sampleData && (scan.status === "COMPLETED" || scan.status === "PARTIAL"));

  useEffect(() => {
    document.documentElement.style.setProperty("--qrypton-nav-width", `${sidebarCollapsed ? 72 : sidebarWidth}px`);
    document.documentElement.dataset.navCollapsed = String(sidebarCollapsed);
    return () => { document.documentElement.style.removeProperty("--qrypton-nav-width"); delete document.documentElement.dataset.navCollapsed; };
  }, [sidebarCollapsed, sidebarWidth]);

  if (!authReady) {
    return (
      <div className="min-h-screen bg-background text-foreground" aria-busy="true">
        <span className="sr-only" role="status">Loading Scans, Findings, and Assets…</span>
        <div aria-hidden="true" className="hidden h-screen w-64 flex-col gap-5 border-r border-border bg-card p-6 lg:fixed lg:flex">
          <div className="h-9 w-36"><Logo tone="on-dark" lockup className="h-9" /></div>
          {Array.from({ length: 7 }, (_, index) => <div key={index} className="h-9 rounded bg-muted" />)}
        </div>
        <div className="lg:pl-64" aria-hidden="true">
          <div className="flex min-h-[55svh] flex-col justify-end gap-5 border-b border-border p-6 sm:p-10 lg:p-16">
            <div className="h-14 w-52 max-w-full rounded bg-muted" />
            <div className="h-4 w-64 max-w-full rounded bg-muted" />
            <div className="h-4 w-full max-w-lg rounded bg-muted" />
          </div>
          <main className="mx-auto max-w-7xl space-y-8 p-4 py-10 sm:p-6 lg:p-8">
            <div className="h-11 rounded border border-border bg-card" />
            <div className="grid gap-3 lg:grid-cols-3">{Array.from({ length: 3 }, (_, index) => <div key={index} className="h-40 rounded-lg border border-border bg-card p-4"><div className="h-5 w-2/3 rounded bg-muted" /><div className="mt-6 h-8 w-1/2 rounded bg-muted" /><div className="mt-4 h-4 w-3/4 rounded bg-muted" /></div>)}</div>
            <div className="h-36 rounded-lg border border-border bg-card" />
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">{Array.from({ length: 4 }, (_, index) => <div key={index} className="h-28 rounded-lg border border-border bg-card" />)}</div>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen overflow-x-hidden bg-background font-sans text-foreground antialiased">
      <Sidebar active={activeSection} onNavigate={navigateTo} width={sidebarWidth} onWidthChange={setSidebarWidth} collapsed={sidebarCollapsed} onToggleCollapsed={() => setSidebarCollapsed((value) => !value)} />
      <div
        className="pl-0 qrypton-motion lg:pl-[var(--sidebar-w)]"
        style={{ "--sidebar-w": `${sidebarCollapsed ? 72 : sidebarWidth}px` } as React.CSSProperties}
      >
      <header className="absolute right-5 top-4 z-30 flex items-center gap-4 rounded-full border border-border bg-card px-4 py-2 backdrop-blur sm:right-8">
        <span className="grid size-8 place-items-center rounded-full bg-muted text-foreground" aria-label="Signed-in user">
          <Logo tone="on-dark" className="size-5" />
        </span>
        <span className="hidden max-w-[180px] truncate text-xs font-medium text-foreground sm:block" title={`Hello, ${loggedInUser}`}>Hello, {loggedInUser}</span>
      </header>
      <section className="qrypton-hero relative isolate flex min-h-[85svh] items-center overflow-hidden px-6 py-14 sm:px-10 lg:px-16">
        <div className="qrypton-hero-grid" aria-hidden="true" />
        <div className="relative z-10 mx-auto grid w-full max-w-7xl items-end gap-12 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="qrypton-hero-copy">
            <h1 className="qrypton-wordmark" aria-label="QRYPTON"><span aria-hidden="true" className="qrypton-hero-wordmark"><Logo tone="on-dark" className="qrypton-hero-initial" /><span>RYPTON</span></span></h1>
            <p className="qrypton-tagline">Discover. Assess. Evolve.</p>
            <p className="mt-8 max-w-md text-base leading-7 text-muted-foreground sm:text-lg">Cryptographic discovery, quantum exposure modelling, and PQC migration evidence — in one security control plane.</p>
            <button onClick={() => document.getElementById("new-scan")?.scrollIntoView({ behavior: "instant" })} className="qrypton-scroll-cue mt-10">
              Explore your cryptographic horizon <ArrowDown className="size-4" />
            </button>
          </div>
          <div className="relative self-center justify-self-center lg:justify-self-end"><HeroLogo /></div>
        </div>
      </section>

      <main className="relative mx-auto max-w-7xl space-y-8 px-4 py-16 sm:px-6 lg:px-8">
        <nav aria-label="Breadcrumb" className="sticky top-0 z-20 rounded border border-border bg-background p-3 text-sm"><Link href="/">Workspace</Link> / {inventoryView.application || activeScanMeta?.target || "All applications"} / {activeScanId ?? "Latest scan"}</nav>
        {(loading || refreshing) && !posture ? <p role="status" className="rounded border border-border bg-card p-4 text-sm text-muted-foreground">Loading canonical assessment data…</p> : <RoleHome inventory={inventory} scans={scanHistory.map(s => ({scan_id: s.id, target: s.target}))} onSelect={openFindingDrawer} />}
        {activeScan?.status === "PARTIAL" && <p role="status" className="rounded-lg border border-border bg-muted p-4 text-sm"><strong>Partial Scan.</strong> Some scanners did not complete. Findings and risk totals reflect only recorded evidence; review Scan history for coverage before comparing or exporting.</p>}
        {sampleScans.length > 0 && <div role="status" className="flex flex-wrap items-center justify-between gap-3 border border-border bg-muted px-4 py-3 text-sm"><p><strong>Sample data</strong> · {activeSample ? "Viewing synthetic payment app findings." : "Synthetic payment app scans are available in history."} No customer assets or measurements are shown in sample records.</p><button type="button" disabled={sampleLoading} onClick={() => { void removeSampleWorkspace(); }} className="font-semibold text-primary hover:underline disabled:opacity-50">Remove sample data</button></div>}
        <ScanNotifications onSettled={onBackgroundScanSettled} />
        {scanSuccessMessage && <p role="status" className="rounded-md border border-border p-4 text-sm">{scanSuccessMessage} <a href="#your-scans" className="text-primary underline">Open Scan History</a></p>}
        <section id="new-scan" className="qrypton-scan-portal">
          <div><h2>Discover. Assess. Evolve.</h2><p>Map every algorithm, certificate and vulnerable dependency in your environment.</p><button type="button" disabled={sampleLoading} onClick={() => { void loadSampleWorkspace(); }} className="mt-4 text-sm font-semibold text-primary hover:underline disabled:opacity-50">{sampleLoading ? "Loading sample workspace…" : "Try with sample payment app"}</button></div>
          <button onClick={openScan} className="qrypton-plus-button" aria-label="Start a new cryptographic scan"><Plus /></button>
          <button onClick={openScan} className="qrypton-scan-label">New scan <span>→</span></button>
        </section>
        {/* Connection Error Banner if backend fails */}
        {apiError && (
          <div className="p-4 rounded-xl border border-border bg-muted backdrop-blur-md flex items-center justify-between gap-4">
            <div className="flex items-center gap-4 text-secondary text-sm">
              <XCircle className="h-5 w-5 text-secondary flex-shrink-0" />
              <span>{apiError}</span>
            </div>
            <button
              onClick={() => loadData(false, activeScanId ?? scanHistory.find(scan => scan.status === "COMPLETED" || scan.status === "PARTIAL")?.id)}
              className="px-4 py-1.5 rounded-lg bg-muted hover:bg-muted text-secondary text-xs font-medium border border-border qrypton-motion"
            >
              Retry Connection
            </button>
          </div>
        )}

        {scanSubmitting && (
          <div className="qrypton-card flex items-center gap-4 border-border p-4" role="status" aria-live="polite">
            <Loader2 className="size-5 shrink-0  text-secondary" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold">Scan in progress</p>
              <p className="mt-0.5 text-xs text-muted-foreground">Collecting cryptographic evidence. Use Show Results in the scan workflow when this run completes.</p>
            </div>
          </div>
        )}

        {scanError && (
          <div className="flex items-start justify-between gap-4 rounded-xl border border-border bg-muted p-4" role="alert">
            <div className="flex items-start gap-4 text-sm text-secondary">
              <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-secondary" />
              <div>
                <p className="font-semibold text-secondary">Scan failed</p>
                <p className="mt-1 text-secondary">{scanError}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setScanError(null)}
              className="rounded-lg border border-border px-4 py-1.5 text-xs font-medium text-secondary hover:bg-muted"
            >
              Dismiss
            </button>
          </div>
        )}

        {!loading && !refreshing && ((posture && posture.total_findings === 0) || (!posture && !apiError && scanHistory.length === 0)) && (
          <section className="qrypton-card flex flex-col items-center justify-center text-center p-8 sm:p-12 space-y-4">
            <div className="flex size-14 items-center justify-center rounded-2xl bg-muted text-secondary border border-border">
              <Shield className="size-7" aria-hidden="true" />
            </div>
            <div className="max-w-md space-y-2">
              <h2 className="text-2xl font-semibold tracking-normal">Run First Cryptographic Scan</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Connect your repository or runtime infrastructure to discover legacy algorithms, map cryptographic evidence, and construct your post-quantum migration roadmap.
              </p>
            </div>
            <button
              onClick={openScan}
              className="inline-flex min-h-10 items-center justify-center rounded-xl bg-primary px-6 text-sm font-semibold text-primary-foreground shadow-md qrypton-motion hover:opacity-90 active:[transform:scale(0.98)]"
            >
              Run First Cryptographic Scan
            </button>
            <button type="button" disabled={sampleLoading} onClick={() => { void loadSampleWorkspace(); }} className="min-h-10 rounded-md border border-border px-5 text-sm font-semibold text-primary hover:bg-muted disabled:opacity-50">{sampleLoading ? "Loading sample workspace…" : "Load sample workspace"}</button>
          </section>
        )}

        <section aria-labelledby="attention-heading" className="qrypton-card overflow-hidden">
          <div className="flex flex-col gap-4 border-b border-border p-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 id="attention-heading" className="text-xl font-semibold tracking-normal">What Needs Attention?</h2>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">Start with the highest-impact exposure and use the evidence drawer to assign the next action.</p>
            </div>
            <button onClick={() => document.getElementById("inventory")?.scrollIntoView({ behavior: "instant" })} className="inline-flex min-h-10 items-center justify-center rounded-md border border-border px-4 text-sm font-semibold text-foreground qrypton-motion hover:bg-muted">Review inventory <ChevronRight data-icon="inline-end" /></button>
          </div>
          <div className="grid gap-0 divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <div className="flex items-start gap-4 p-6"><div className="rounded-md bg-muted p-2 text-secondary"><AlertTriangle className="size-4" aria-hidden="true" /></div><div><p className="text-2xl font-semibold tabular-nums">{posture?.critical_findings_count ?? "—"}</p><p className="text-sm font-medium">Critical findings</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Prioritize remediation before the next review.</p></div></div>
            <div className="flex items-start gap-4 p-6"><div className="rounded-md bg-muted p-2 text-secondary"><ShieldAlert className="size-4" aria-hidden="true" /></div><div><p className="text-sm tabular-nums font-semibold">{posture ? `Critical ${moscaDistribution.critical} · High ${moscaDistribution.high}` : "Mosca data unavailable"}</p><p className="text-sm font-medium"><GlossaryText>{"Mosca urgency distribution"}</GlossaryText></p><p className="mt-1 text-xs leading-5 text-muted-foreground">{posture ? `Medium ${moscaDistribution.medium} · Low ${moscaDistribution.low} · N/A ${moscaDistribution.not_applicable} · Unknown ${moscaDistribution.unknown}` : "Waiting for canonical backend results."}</p></div></div>
            <div className="flex items-start gap-4 p-6"><div className="rounded-md bg-muted p-2 text-secondary"><Search className="size-4" aria-hidden="true" /></div><div><p className="text-2xl font-semibold tabular-nums">{posture?.unique_asset_ids ?? "—"}</p><p className="text-sm font-medium">Assets to validate</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Open the inventory to inspect evidence and ownership.</p></div></div>
          </div>
        </section>

        {/* --- Top KPI Cards --- */}
        <section id="dashboard" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm tabular-nums normal-case tracking-normal text-muted-foreground flex items-center gap-2">
              <Layers className="h-4 w-4 text-secondary" />
              Executive Cryptographic Posture
            </h2>
            {posture?.run_status && (
              <span className="text-xs tabular-nums text-muted-foreground flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-muted " />
                Status: {posture.run_status.toUpperCase()}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Total Findings */}
            <div className="rounded-2xl border border-border bg-muted p-6 backdrop-blur-md hover:border-border qrypton-motion">
              <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground mb-4">
                <span className="text-xs tabular-nums normal-case tracking-normal">Total Findings</span>
                <div className="p-2 rounded-lg bg-muted text-secondary">
                  <FileText className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl tabular-nums font-semibold text-foreground">
                  {posture?.total_findings ?? "—"}
                </span>
                <span className="text-xs text-muted-foreground tabular-nums">Discovered Assets</span>
              </div>
            </div>

            {/* 2. Critical & High Counts */}
            <div className="rounded-2xl border border-border bg-muted p-6 backdrop-blur-md hover:border-border qrypton-motion">
              <div className="flex items-center justify-between text-muted-foreground mb-3">
                <span className="text-xs tabular-nums normal-case tracking-normal">
                  Critical / High Risk
                </span>
                <div className="p-2 rounded-lg bg-muted text-secondary border border-border">
                  <AlertTriangle className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl tabular-nums font-semibold text-secondary">
                  {posture?.critical_findings_count ?? "—"}
                </span>
                <span className="text-xl tabular-nums font-semibold text-secondary">
                  / {posture?.high_findings_count ?? "—"}
                </span>
                <span className="ml-auto text-xs text-muted-foreground tabular-nums">Immediate Action</span>
              </div>
            </div>

            {/* 3. Scanned Assets */}
            <div className="rounded-2xl border border-border bg-muted p-6 backdrop-blur-md hover:border-border qrypton-motion">
              <div className="flex items-center justify-between text-muted-foreground mb-3">
                <span className="text-xs tabular-nums normal-case tracking-normal">Scanned Assets</span>
                <div className="p-2 rounded-lg bg-muted text-secondary border border-border">
                  <Shield className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl tabular-nums font-semibold text-foreground">
                  {posture?.unique_asset_ids ?? "—"}
                </span>
                <span className="text-xs text-muted-foreground tabular-nums">Inventories Tracked</span>
              </div>
            </div>

            {/* 4. Policy Status */}
            <div className="rounded-2xl border border-border bg-muted p-6 backdrop-blur-md hover:border-border qrypton-motion">
              <div className="flex items-center justify-between text-muted-foreground mb-3">
                <span className="text-xs tabular-nums normal-case tracking-normal">Policy Compliance</span>
                {!posture ? (
                  <span className="text-xs font-semibold text-muted-foreground">UNAVAILABLE</span>
                ) : posture.policy_passed ? (
                  <div className="p-2 rounded-lg bg-muted text-secondary border border-border">
                    <CheckCircle2 className="h-4 w-4" />
                  </div>
                ) : (
                  <div className="p-2 rounded-lg bg-muted text-secondary border border-border">
                    <ShieldAlert className="h-4 w-4" />
                  </div>
                )}
              </div>
              <div className="flex flex-col">
                {!posture ? (
                  <span className="text-xs text-muted-foreground tabular-nums">No canonical posture result loaded.</span>
                ) : posture.policy_passed ? (
                  <span className="text-2xl tabular-nums font-semibold text-secondary">
                    PASSED
                  </span>
                ) : (
                  <div>
                    <span className="text-2xl tabular-nums font-semibold text-secondary">
                      VIOLATIONS
                    </span>
                    <span className="text-xs text-secondary tabular-nums block truncate">
                      {posture?.policy_violations?.length || 0} non-compliant findings
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <section id={RESULTS_SECTION_ID} aria-labelledby="results-heading" className="space-y-4 scroll-mt-24">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 id="results-heading" className="mt-1 text-xl font-semibold tracking-normal">Results</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {activeScanMeta
                  ? `Showing only findings for “${activeScanMeta.target}” (${activeScanMeta.id}).`
                  : activeScanId
                    ? `Showing inventory and findings for ${activeScanId}.`
                    : "Inventory, evidence, and risk from the latest completed scan. Run a scan to see its dedicated result here."}
              </p>
              {activeScanMeta && (
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                  <span className="inline-flex items-center rounded-full border border-border bg-muted px-2.5 py-1 tabular-nums font-semibold text-secondary">
                    {activeScanMeta.id}
                  </span>
                  {activeScanMeta.target_type && (
                    <span className="inline-flex items-center rounded-full border border-border px-2.5 py-1 tabular-nums text-muted-foreground">
                      {activeScanMeta.target_type}
                    </span>
                  )}
                  <span className="inline-flex items-center rounded-full border border-border px-2.5 py-1 tabular-nums capitalize text-muted-foreground">
                    {activeScanMeta.environment}
                  </span>
                  <span className="inline-flex items-center rounded-full border border-border bg-muted px-2.5 py-1 font-semibold text-secondary">
                    {posture?.total_findings ?? "—"} findings
                  </span>
                </div>
              )}
            </div>
            {activeScanId && latestDashboardScan && activeScanId !== latestDashboardScan.id && (
              <button
                type="button"
                onClick={() => {
                  setActiveScanId(latestDashboardScan.id);
                  setActiveScanMeta({
                    id: latestDashboardScan.id,
                    target: latestDashboardScan.target,
                    target_type: latestDashboardScan.target_type,
                    environment: latestDashboardScan.environment,
                  });
                  void loadData(true, latestDashboardScan.id);
                }}
                className="text-xs font-semibold text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
              >
                Show latest scan instead
              </button>
            )}
          </div>
          <div id="results-quick-export" />
          {posture && <div className="qrypton-card p-6" aria-label="Active metrics overview">
            <h2 className="text-base font-semibold">Active Metrics Overview</h2>
            <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-md border border-border p-4"><p className="text-2xl font-semibold tabular-nums">{posture?.unique_asset_ids ?? 0}</p><p className="text-sm font-medium">Total assets</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Distinct cryptographic assets in this run.</p></div>
              <div className="rounded-md border border-border p-4"><p className="text-2xl font-semibold tabular-nums"><span className="text-secondary">{posture?.critical_findings_count ?? 0}</span><span className="text-muted-foreground"> / </span><span className="text-secondary">{posture?.high_findings_count ?? 0}</span><span className="text-muted-foreground"> / </span>{posture?.medium_findings_count ?? 0}<span className="text-muted-foreground"> / </span>{posture?.low_findings_count ?? 0}</p><p className="text-sm font-medium">Final risk tiers</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Critical / high / medium / low, from persisted assessments.</p></div>
              <div className="rounded-md border border-border p-4"><p className="text-sm tabular-nums font-semibold">C {moscaDistribution.critical} · H {moscaDistribution.high} · M {moscaDistribution.medium} · L {moscaDistribution.low}</p><p className="mt-1 text-sm font-medium"><GlossaryText>{"Mosca urgency distribution"}</GlossaryText></p><p className="mt-1 text-xs leading-5 text-muted-foreground">N/A {moscaDistribution.not_applicable} · Unknown {moscaDistribution.unknown}; per-finding persisted outcomes.</p></div>
              <div className="rounded-md border border-border p-4"><p className="text-2xl font-semibold tabular-nums">{posture?.total_findings ?? 0}</p><p className="text-sm font-medium">Total findings</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Status: {posture?.run_status ? posture.run_status.replace(/_/g, " ") : "no completed run"}.</p></div>
              <div className="rounded-md border border-border p-4"><p className="text-2xl font-semibold tabular-nums">{posture?.informational_findings_count ?? 0} / {posture?.unknown_findings_count ?? 0} / {posture?.unassessed_findings_count ?? 0}</p><p className="text-sm font-medium">Informational / unknown / unassessed</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Unknown and unassessed remain separate from risk tiers.</p></div>
            </div>
          </div>}
          {posture && activeScanId && inventory.length === 0 ? (
            <div className="qrypton-card p-8 text-center" role="status">
              <p className="text-sm font-semibold">No findings stored for this scan yet.</p>
              <p className="mt-1 text-xs text-muted-foreground">
                The run {activeScanId} completed but returned an empty inventory. Try another target or re-run the scan.
              </p>
            </div>
          ) : posture ? (
            <CryptoInventory key={activeScanId ?? "latest"} items={inventory} state={inventoryView} onViewChange={updateInventoryView} onSelect={openFindingDrawer} runId={activeScanId} onActionsComplete={refreshInvestigation} sampleData={activeSample} />
          ) : null}
        </section>

        {posture ? <RiskPrioritization
          heatmap={heatmap}
          inventory={inventory}
          roadmap={roadmap}
          state={inventoryView}
          onViewChange={updateInventoryView}
          selected={selectedHeatmapCell}
          onFilter={(cell) => updateInventoryView({ urgency: cell?.urgency ?? "", criticality: cell?.criticality ?? "", finding: "" })}
          onSelect={openFindingDrawer}
          sampleData={activeSample}
        /> : <section className="qrypton-card p-6 text-sm text-muted-foreground" aria-live="polite">Risk matrix and migration queue are unavailable until canonical backend results load.</section>}

        <section id="reports" aria-labelledby="reports-heading">
          <div className="qrypton-card p-6">
            <h2 id="reports-heading" className="text-xl font-semibold"><GlossaryText>{"CBOM & Reports"}</GlossaryText></h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground"><GlossaryText>{"Download the persisted CycloneDX CBOM for a scan, or use that scan’s report actions for canonical CSV, HTML, and PDF exports."}</GlossaryText></p>
            <ScanExport runId={activeScanId ?? scanHistory.find((scan) => scan.status === "COMPLETED")?.id ?? null} />
          </div>
        </section>

        <section id="integrations" className="qrypton-card p-6" aria-labelledby="integrations-heading"><h2 id="integrations-heading" className="text-xl font-semibold">Integrations</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">Connect source control, CI/CD, container registries, and cloud KMS through organization-managed credentials. New scans never collect secrets in the workflow.</p><div className="mt-4 flex flex-wrap gap-2 text-xs"><span className="rounded-full border border-border px-4 py-1.5">Source control</span><span className="rounded-full border border-border px-4 py-1.5">Container registry</span><span className="rounded-full border border-border px-4 py-1.5">Cloud KMS</span><span className="rounded-full border border-border px-4 py-1.5">CI/CD</span></div></section>

        {NETWORK_SAMPLE_MODE ? <LiveTelemetry /> : null}
        <div className="space-y-4 scroll-mt-24">
          <ScanComparison scans={scanHistory} backView={writeInventoryView("", inventoryView)} />
          <ScanHistory
            scans={scanHistory}
            quickExportTargetId="results-quick-export"
            page={scanHistoryPage}
            pageCount={Math.ceil(scanHistoryTotal / SCANS_PER_PAGE)}
            onPageChange={(page) => { void refreshScanHistory(page); }}
            onSelectScan={(scanId) => {
              void handleSelectHistoricalScan(scanId);
            }}
            onDelete={(scanId) => { void deleteHistoricalScan(scanId); }}
          />
        </div>

      </main>
      </div>

      <FindingDetail
        fullPageHref={findingDetail ? `/finding?finding_id=${encodeURIComponent(findingDetail.finding.id)}&run_id=${encodeURIComponent(activeScanId ?? "")}&view=${encodeURIComponent(writeInventoryView("", inventoryView))}` : undefined}
        open={isDrawerOpen}
        loading={detailLoading}
        detail={findingDetail}
        roadmapItem={findingDetail ? roadmap.find((item) => item.finding_id === findingDetail.finding.id) as FindingRoadmapItem | undefined : undefined}
        onClose={closeDrawer}
        copiedId={copiedId}
        onCopy={copyToClipboard}
        sampleData={activeSample}
      />

      <ScanWorkflow
        open={isScanModalOpen}
        onClose={() => {
          setIsScanModalOpen(false);
          if (!scanSubmitting && !scanPolling) resetScanOutcome();
        }}
        progress={scanProgress}
        form={scanForm}
        setForm={setScanForm}
        onSubmit={handleStartScan}
        onReset={resetScanOutcome}
        submitting={scanSubmitting}
        successMessage={scanSuccessMessage}
        submitError={scanError}
        polling={scanPolling}
        phaseMessage={scanPhaseMessage}
        elapsedMs={scanElapsedMs}
        onShowResults={() => {
          setIsScanModalOpen(false);
          if (completedScanId) revealResults(completedScanId);
        }}
      />

    </div>
  );
}
