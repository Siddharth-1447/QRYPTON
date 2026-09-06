"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import { AuthFlow } from "@/components/auth-flow";
import { ScanWorkflow } from "@/components/scan-workflow";
import { CryptoInventory } from "@/components/crypto-inventory";
import { FindingDetail } from "@/components/finding-detail";
import { RiskPrioritization } from "@/components/risk-prioritization";
import { LiveTelemetry } from "@/components/live-telemetry";
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
  Sparkles,
  RefreshCw,
  ChevronRight,
  Lock,
  X,
  Filter,
  Moon,
  Sun,
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

export default function QryptonCommandCenter() {
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

  // --- Theme (Light / Executive Dark) ---
  const [theme, setTheme] = useState<"light" | "dark">("light");

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [theme]);

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

  const [scanForm, setScanForm] = useState({
    target_type: "source_repo",
    repository: "https://github.com/org/payments-core",
    branch: "main",
    environment: "production",
    business_criticality: "critical",
    data_lifetime: 7.0, // X
    migration_time: 4.0, // Y
    crqc_horizon: 8.0, // Z
  });

  // --- Data Fetching ---
  const loadData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);
      setApiError(null);

      const [postureRes, invRes, moscaRes, heatmapRes, roadmapRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/posture`),
        fetch(`${API_BASE}/api/v1/inventory`),
        fetch(`${API_BASE}/api/v1/mosca/eval`),
        fetch(`${API_BASE}/api/v1/heatmap`),
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

      setPosture(postureData);
      setInventory(invData || []);
      setMoscaPoints(moscaData || []);
      setHeatmap(heatmapData || []);
      setRoadmap(roadmapData || []);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setApiError(err.message);
      } else {
        setApiError("An unexpected error occurred while communicating with the QRYPTON backend.");
      }
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
          fetch(`${API_BASE}/api/v1/heatmap`),
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
          setHeatmap(heatmapData || []);
          setRoadmap(roadmapData || []);
        }
      } catch (err: unknown) {
        if (!ignore) {
          if (err instanceof Error) {
            setApiError(err.message);
          } else {
            setApiError("An unexpected error occurred while communicating with the QRYPTON backend.");
          }
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
  }, []);

  // --- Fetch Single Finding Detail ---
  const openFindingDrawer = async (findingId: string) => {
    setIsDrawerOpen(true);
    setDetailLoading(true);
    setFindingDetail(null);

    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/${encodeURIComponent(findingId)}`);
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

  // --- Scan Submission ---
  const handleStartScan = async () => {
    try {
      setScanSubmitting(true);
      const payload = {
        target_type: scanForm.target_type,
        repository: scanForm.repository,
        environment: scanForm.environment,
        business_criticality: scanForm.business_criticality,
        data_lifetime: Number(scanForm.data_lifetime),
        migration_time: Number(scanForm.migration_time),
        crqc_horizon: Number(scanForm.crqc_horizon),
      };

      const res = await fetch(`${API_BASE}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        throw new Error(`Scan submission failed (${res.status})`);
      }

      setScanSuccessMessage("Cryptographic scan successfully initialized and analyzed!");
      setTimeout(() => {
        setIsScanModalOpen(false);
        setScanSuccessMessage(null);
              loadData(true);
      }, 1200);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to trigger scan");
    } finally {
      setScanSubmitting(false);
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

  if (!authReady) {
    return <AuthFlow onComplete={() => setAuthReady(true)} />;
  }

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
    <div className="min-h-screen bg-background font-sans text-foreground antialiased">
      {/* --- Sticky Workspace Header --- */}
      <header className="sticky top-0 z-40 border-b border-border bg-card/95 backdrop-blur transition-all">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-500/20 ring-1 ring-white/20">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <span className="text-lg font-black tracking-wider text-white font-mono flex items-center gap-2">
                  QRYPTON
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold tracking-normal">
                    PQC COMMAND
                  </span>
                </span>
              </div>
            </div>

            {/* Anchor Navigation */}
            <nav className="hidden md:flex items-center gap-1 text-xs font-medium text-slate-400">
              <a
                href="#dashboard"
                className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                Dashboard
              </a>
              <a
                href="#live-scanner"
                className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                Live Scanner
              </a>
              <a
                href="#heatmap"
                className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                Mosca Heatmap
              </a>
              <a
                href="#roadmap"
                className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                PQC Roadmap
              </a>
              <a
                href="#inventory"
                className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                Crypto Inventory
              </a>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
              title={theme === "dark" ? "Switch to light mode" : "Switch to Executive dark mode"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              className="p-2 rounded-xl border border-slate-800 hover:border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all active:scale-95"
            >
              {theme === "dark" ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
            </button>

            <button
              onClick={() => loadData(true)}
              disabled={refreshing}
              title="Refresh inventory and postures"
              className="p-2 rounded-xl border border-slate-800 hover:border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all active:scale-95 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
            </button>

            <button
              onClick={() => {
                              setIsScanModalOpen(true);
              }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-medium text-xs tracking-wide shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 border border-white/10 active:scale-95 transition-all"
            >
              <Sparkles className="h-3.5 w-3.5" />
              + New Scan
            </button>
          </div>
        </div>
      </header>

      {/* --- Main Content Area --- */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
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

        <section aria-labelledby="scan-status-heading" className="qrypton-card p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div><p className="qrypton-kicker">Coverage signal</p><h2 id="scan-status-heading" className="mt-1 text-base font-semibold">Recent scan activity</h2></div>
            <span className={`inline-flex w-fit items-center gap-2 rounded-full px-2.5 py-1 text-xs font-semibold ${posture?.run_status?.toLowerCase().includes("fail") ? "qrypton-risk-critical" : posture?.run_status?.toLowerCase().includes("run") || posture?.run_status?.toLowerCase().includes("progress") ? "qrypton-risk-medium" : "qrypton-risk-success"}`}><span className="size-1.5 rounded-full bg-current" />{posture?.run_status ? posture.run_status.replace(/_/g, " ") : "No scan status"}</span>
          </div>
          <div className="mt-4 flex flex-col gap-3 rounded-md border border-border bg-muted/40 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div><p className="text-sm font-medium">{posture?.run_status?.toLowerCase().includes("run") ? "A scan is currently evaluating your cryptographic estate." : posture?.total_findings ? "Latest scan completed with actionable findings." : "No completed scan data is available yet."}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{posture?.scanner_failed_count ? `${posture.scanner_failed_count} scanner failed. Review coverage before relying on this posture.` : "Coverage and findings are reflected in the command center below."}</p></div>
            <button onClick={() => setIsScanModalOpen(true)} className="inline-flex min-h-9 shrink-0 items-center justify-center rounded-md bg-primary px-3 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90">Run new scan</button>
          </div>
        </section>

        {/* --- Mosca Urgency Warning Banner ($X + Y > Z$) --- */}
        {moscaViolation && (
          <div
            id="mosca-banner"
            className="relative overflow-hidden rounded-2xl border border-rose-500/50 bg-gradient-to-r from-rose-950/80 via-slate-900/90 to-rose-950/60 p-6 backdrop-blur-xl shadow-2xl shadow-rose-950/50"
          >
            <div className="absolute top-0 right-0 transform translate-x-8 -translate-y-8 w-48 h-48 bg-rose-500/10 rounded-full blur-2xl pointer-events-none" />
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
              <div className="flex items-start gap-4">
                <div className="p-3 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-400 mt-1">
                  <ShieldAlert className="h-7 w-7 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-500/30 text-rose-200 border border-rose-400/40">
                      CRITICAL MOSCA TIMELINE EXPOSURE
                    </span>
                    <span className="text-xs font-mono text-rose-400/80">
                      Theorem: X + Y &gt; Z Deficit
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white tracking-tight">
                    Quantum Decryption Vulnerability Detected (Harvest Now, Decrypt Later)
                  </h3>
                  <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
                    Data confidentiality lifetime (
                    <strong className="text-rose-300 font-mono">X = {moscaViolation.x} yrs</strong>)
                    plus required cryptographic migration effort (
                    <strong className="text-amber-300 font-mono">Y = {moscaViolation.y} yrs</strong>)
                    exceeds the anticipated Cryptanalytically Relevant Quantum Computer horizon (
                    <strong className="text-cyan-300 font-mono">Z = {moscaViolation.z} yrs</strong>
                    ). High-value secrets are vulnerable to retrospective harvest.
                  </p>
                </div>
              </div>

              {/* Timeline metrics display box */}
              <div className="flex items-center gap-3 bg-slate-950/80 border border-rose-500/30 rounded-xl p-4 font-mono text-xs shadow-inner">
                <div className="text-center px-3 border-r border-slate-800">
                  <div className="text-[10px] text-slate-400 uppercase">X + Y Time</div>
                  <div className="text-base font-bold text-rose-400">
                    {moscaViolation.x + moscaViolation.y} yrs
                  </div>
                </div>
                <div className="text-center px-3 border-r border-slate-800">
                  <div className="text-[10px] text-slate-400 uppercase">Z Horizon</div>
                  <div className="text-base font-bold text-cyan-400">{moscaViolation.z} yrs</div>
                </div>
                <div className="text-center px-3">
                  <div className="text-[10px] text-rose-400 uppercase font-bold">Deficit</div>
                  <div className="text-base font-bold text-rose-500">
                    +{moscaViolation.deficit.toFixed(1)} yrs
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

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

        <LiveTelemetry />

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
                      key={item.finding_id || idx}
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
                              key={i}
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

        <CryptoInventory items={inventory} query={search} onQueryChange={setSearch} onSelect={openFindingDrawer} onClear={() => { setSearch(""); setSelectedHeatmapCell(null); }} />

        {/* Legacy inventory markup retained for API compatibility; the unified workspace above is the visible presentation. */}
        {/* --- Searchable Cryptographic Inventory Table --- */}
        <section
          id="legacy-inventory"
          className="hidden"
        >
          <div className="p-6 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                <Lock className="h-4 w-4 text-cyan-400" />
                Cryptographic Findings Inventory
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Click any row to open the deep evidence provenance &amp; AST code drawer
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              {selectedHeatmapCell && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
                  <Filter className="h-3 w-3" />
                  <span>
                    {selectedHeatmapCell.urgency.toUpperCase()} /{" "}
                    {selectedHeatmapCell.criticality.toUpperCase()}
                  </span>
                  <button
                    onClick={() => setSelectedHeatmapCell(null)}
                    className="hover:text-white"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              )}

              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search algorithm or finding ID..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full sm:w-72 bg-slate-950 border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  <th className="px-6 py-3.5 font-medium">Finding ID</th>
                  <th className="px-6 py-3.5 font-medium">Algorithm</th>
                  <th className="px-6 py-3.5 font-medium">Family</th>
                  <th className="px-6 py-3.5 font-medium">Category</th>
                  <th className="px-6 py-3.5 font-medium">Risk Score</th>
                  <th className="px-6 py-3.5 font-medium">Risk Level</th>
                  <th className="px-6 py-3.5 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-xs font-mono">
                {filteredInventory.length > 0 ? (
                  filteredInventory.map((item) => (
                    <tr
                      key={item.finding_id}
                      onClick={() => openFindingDrawer(item.finding_id)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    >
                      <td className="px-6 py-4 font-mono text-slate-400 group-hover:text-cyan-300 transition-colors">
                        <span className="truncate block max-w-[180px]" title={item.finding_id}>
                          {item.finding_id}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-semibold text-white">
                        {item.algorithm_name || "-"}
                      </td>
                      <td className="px-6 py-4 text-slate-300">
                        {item.algorithm_family || "-"}
                      </td>
                      <td className="px-6 py-4 text-slate-300 capitalize">
                        {item.category?.replace(/_/g, " ") || "-"}
                      </td>
                      <td className="px-6 py-4 text-slate-300">
                        {item.risk_score !== null && item.risk_score !== undefined
                          ? item.risk_score.toFixed(1)
                          : "-"}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border ${
                            item.risk_level === "critical"
                              ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                              : item.risk_level === "high"
                              ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                              : item.risk_level === "medium"
                              ? "bg-blue-500/15 text-blue-400 border-blue-500/30"
                              : "bg-slate-700/30 text-slate-300 border-slate-600/30"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              item.risk_level === "critical"
                                ? "bg-rose-400 animate-pulse"
                                : item.risk_level === "high"
                                ? "bg-amber-400"
                                : "bg-slate-400"
                            }`}
                          />
                          {item.risk_level.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <span className="inline-flex items-center gap-1 text-[11px] text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                          Evidence
                          <ChevronRight className="h-3 w-3" />
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="px-6 py-16 text-center text-slate-500 font-mono">
                      <div className="flex flex-col items-center gap-3">
                        <FileText className="h-8 w-8 text-slate-600" />
                        <p>No matching cryptographic inventory records found.</p>
                        {search && (
                          <button
                            onClick={() => setSearch("")}
                            className="text-xs text-cyan-400 underline"
                          >
                            Clear search filters
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>

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
      />
    </div>
  );
}
