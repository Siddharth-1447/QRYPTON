"use client";

import React, { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { History, FileSpreadsheet, FileCode, FileText, CheckCircle2, Trash2, ExternalLink } from "lucide-react";
import { Badge, RiskBadge, Button, Card, CardContent, CardHeader, CardTitle } from "@/components/ui/primitives";
import { API_BASE } from "@/lib/api";
import { REPORT_WORDMARK } from "@/lib/report-wordmark";
import { exportTokenStyles } from "@/lib/export-styles";

export interface ScanHistoryRecord {
  id: string;
  timestamp: string;
  target: string;
  target_type: string;
  environment: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  totalFindings: number;
  status: "COMPLETED" | "PARTIAL" | "RUNNING" | "FAILED";
  sampleData?: boolean;
}

export const TARGET_TYPE_LABELS: Record<string, string> = {
  source_repo: "Source Code",
  source_archive: "Source Archive",
  binary: "Binary",
  dependency_manifest: "Library / Package",
  container_image: "Container",
  cloud_kms: "Cloud KMS",
};

export function targetTypeLabel(targetType: string): string {
  return TARGET_TYPE_LABELS[targetType] ?? (targetType || "Unknown");
}

export const DEFAULT_SCANS: ScanHistoryRecord[] = [];

interface ScanHistoryProps {
  scans?: ScanHistoryRecord[];
  quickExportTargetId?: string;
  page: number;
  pageCount: number;
  onPageChange?: (page: number) => void;
  onSelectScan?: (scanId: string) => void;
  onDelete?: (scanId: string) => void;
}

function escapeHtml(value: unknown): string {
  const entities: Record<string, string> = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  };
  return String(value).replace(/[&<>"']/g, (character) => entities[character] ?? character);
}

export function ScanHistory({ scans = DEFAULT_SCANS, quickExportTargetId, page, pageCount, onPageChange, onSelectScan, onDelete }: ScanHistoryProps) {
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportNotice, setExportNotice] = useState("");
  const [quickExportTarget, setQuickExportTarget] = useState<HTMLElement | null>(null);
  useEffect(() => {
    if (quickExportTargetId) queueMicrotask(() => setQuickExportTarget(document.getElementById(quickExportTargetId)));
  }, [quickExportTargetId]);
  const pageNumbers = Array.from(
    new Set([0, page - 1, page, page + 1, pageCount - 1])
  ).filter((index) => index >= 0 && index < pageCount).sort((left, right) => left - right);

  const downloadPdf = async (scanId: string) => {
    setExporting(`pdf-${scanId}`);
    setExportNotice("");
    try {
      const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(scanId)}/report/pdf`);
      if (!response.ok) throw new Error(`PDF generation failed (HTTP ${response.status})`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `qrypton-executive-report-${scanId}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
      setExportNotice("PDF report ready");
    } catch (error) {
      setExportNotice(error instanceof Error ? error.message : "PDF report unavailable; retry this scan");
    } finally {
      setExporting(null);
    }
  };

  const latestScan = scans.length > 0
    ? (scans.find((s) => s.status === "COMPLETED") ?? scans[0])
    : null;

  const downloadLatestJson = async (scanId: string) => {
    setExporting(`json-${scanId}`);
    setExportNotice("");
    try {
      const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(scanId)}/cbom/export?format=json`);
      if (!response.ok) throw new Error(`CBOM JSON export failed (HTTP ${response.status})`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `qrypton-cbom-${scanId}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
      setExportNotice("CBOM JSON ready");
    } catch (error) {
      setExportNotice(error instanceof Error ? error.message : "CBOM JSON unavailable; retry this scan");
    } finally {
      setExporting(null);
    }
  };

  const downloadLatestHtml = async (scanId: string) => {
    setExporting(`html-${scanId}`);
    setExportNotice("");
    try {
      const meta = scans.find((s) => s.id === scanId);
      const [postureRes, invRes, roadmapRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/posture?run_id=${encodeURIComponent(scanId)}`),
        fetch(`${API_BASE}/api/v1/inventory?run_id=${encodeURIComponent(scanId)}`),
        fetch(`${API_BASE}/api/v1/roadmap?run_id=${encodeURIComponent(scanId)}`),
      ]);
      if (!postureRes.ok || !invRes.ok || !roadmapRes.ok) {
        throw new Error("HTML report data could not be loaded for this scan");
      }
      type PostureData = { total_findings?: number; critical_findings_count?: number; high_findings_count?: number; medium_findings_count?: number; low_findings_count?: number; informational_findings_count?: number; unknown_findings_count?: number; unassessed_findings_count?: number; run_status?: string; policy_passed?: boolean };
      type InvItem = { finding_id: string; algorithm_name?: string | null; algorithm_family?: string | null; identity_label?: string; identity_status?: string; library_name?: string | null; algorithm_variant?: string | null; crypto_role?: string | null; risk_level: string; risk_assessment_state: "assessed" | "unassessed"; business_criticality?: string; confidence: number; category: string; key_size_bits?: number | null };
      type RoadmapItem = { finding_id: string; priority: number; action: string; target_algorithms?: string[] };
      const posture: PostureData = postureRes.ok ? await postureRes.json() as PostureData : {};
      const inv: InvItem[] = invRes.ok ? await invRes.json() as InvItem[] : [];
      const roadmap: RoadmapItem[] = roadmapRes.ok ? await roadmapRes.json() as RoadmapItem[] : [];
      const critCount = Number(posture.critical_findings_count ?? 0);
      const highCount = Number(posture.high_findings_count ?? 0);
      const medCount = Number(posture.medium_findings_count ?? 0);
      const lowCount = Number(posture.low_findings_count ?? 0);
      const informationalCount = Number(posture.informational_findings_count ?? 0);
      const unknownCount = Number(posture.unknown_findings_count ?? 0);
      const unassessedCount = Number(posture.unassessed_findings_count ?? 0);
      const total = Number(posture.total_findings ?? inv.length ?? 0);
      const severityColor: Record<string, string> = {
        critical: "var(--critical)", high: "var(--high)", medium: "var(--medium-text)", low: "var(--low)", informational: "var(--text-secondary)", unknown: "var(--text-muted)", unassessed: "var(--text-muted)"
      };
      const severityCounts: Record<string, number> = { critical: critCount, high: highCount, medium: medCount, low: lowCount, informational: informationalCount, unknown: unknownCount, unassessed: unassessedCount };
      const pctOf = (n: number) => total > 0 ? ((n / total) * 100).toFixed(1) + "%" : "0%";
      const { renderToStaticMarkup } = await import("react-dom/server");
      const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>QRYPTON PQC Assessment Report — ${escapeHtml(scanId)}</title>
  <style>
    ${await exportTokenStyles()}
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-variant-numeric: tabular-nums; background: var(--background); color: var(--text-primary); padding: 2rem; line-height: 1.5; }
    .header { margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 2px solid var(--text-primary); }
    .kicker { font-size: var(--type-12); font-weight: var(--weight-semibold); letter-spacing: 0; text-transform: none; color: var(--text-primary); margin-bottom: 0.25rem; }
    h1 { font-size: var(--type-28); font-weight: var(--weight-semibold); letter-spacing: 0; color: var(--text-primary); margin-bottom: 0.5rem; }
    .meta { font-size: var(--type-12); color: var(--text-muted); }
    h2 { font-size: 1rem; font-weight: var(--weight-semibold); color: var(--text-primary); margin: 1.5rem 0 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; }
    .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem; }
    .kpi-value { font-size: var(--type-28); font-weight: var(--weight-semibold); }
    .kpi-label { font-size: var(--type-12); color: var(--text-muted); text-transform: none; letter-spacing: 0; margin-top: 0.25rem; }
    .bar-chart { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem; margin-bottom: 1.5rem; }
    .bar-row { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.6rem; }
    .bar-label { width: 70px; font-size: var(--type-12); font-weight: var(--weight-semibold); text-transform: none; color: var(--text-muted); flex-shrink: 0; }
    .bar-track { flex: 1; background: var(--surface-subtle); border-radius: 9999px; height: 22px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 9999px; display: flex; align-items: center; padding-left: 8px; font-size: var(--type-12); font-weight: var(--weight-semibold); color: var(--surface); min-width: 2px; }
    .bar-count { width: 60px; text-align: right; font-weight: var(--weight-semibold); font-size: var(--type-12); }
    table { width: 100%; border-collapse: collapse; font-size: var(--type-12); background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }
    th { background: var(--surface-subtle); color: var(--text-primary); font-weight: var(--weight-semibold); text-transform: none; font-size: var(--type-12); letter-spacing: 0; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
    tr { height: var(--table-row-height); } td { padding: 0 16px; border-bottom: 1px solid var(--surface-subtle); vertical-align: top; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: var(--type-12); font-weight: var(--weight-semibold); text-transform: none; }
    .roadmap-item { border-left: 3px solid var(--text-primary); padding: 0.75rem 1rem; margin-bottom: 0.75rem; background: var(--surface-subtle); border-radius: 0 8px 8px 0; }
    .roadmap-priority { font-size: var(--type-12); font-weight: var(--weight-semibold); text-transform: none; color: var(--text-primary); margin-bottom: 0.25rem; }
    .roadmap-action { font-size: var(--type-12); color: var(--text-primary); }
    .roadmap-algos { margin-top: 0.25rem; font-size: var(--type-12); color: var(--text-muted); }
    .footer { text-align: center; color: var(--text-muted); font-size: var(--type-12); margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }
  </style>
</head>
<body>
  <div class="header">
    <div class="kicker">${REPORT_WORDMARK} · Post-Quantum Cryptography Platform</div>
    <h1>Security Assessment Report</h1>
    <div class="meta">Scan ID: <strong>${escapeHtml(scanId)}</strong> &nbsp;&middot;&nbsp; Target: <strong>${escapeHtml(meta?.target ?? "Unknown")}</strong> &nbsp;&middot;&nbsp; Type: <strong>${escapeHtml(meta?.target_type ?? "unknown")}</strong> &nbsp;&middot;&nbsp; Generated: <strong>${escapeHtml(new Date().toLocaleString())}</strong></div>
  </div>

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-value" style="color:var(--critical)">${critCount}</div><div class="kpi-label">Critical</div></div>
    <div class="kpi"><div class="kpi-value" style="color:var(--high)">${highCount}</div><div class="kpi-label">High</div></div>
    <div class="kpi"><div class="kpi-value" style="color:var(--text-secondary)">${informationalCount}</div><div class="kpi-label">Informational</div></div>
    <div class="kpi"><div class="kpi-value" style="color:var(--text-primary)">${total}</div><div class="kpi-label">Total Findings</div></div>
  </div>

  <h2>Risk Distribution</h2>
  <div class="bar-chart">
    ${(["critical", "high", "medium", "low", "informational", "unknown", "unassessed"] as const).map((sev) => {
      const count = severityCounts[sev];
      const pct = total > 0 ? Math.round((count / total) * 100) : 0;
      return `<div class="bar-row"><span class="bar-label">${sev}</span><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${severityColor[sev]}">${pct > 8 ? pct + "%" : ""}</div></div><span class="bar-count" style="color:${severityColor[sev]}">${count}</span></div>`;
    }).join("")}
    <div style="margin-top:0.5rem;font-size:var(--type-12);color:var(--text-muted)">Critical: ${pctOf(critCount)} · High: ${pctOf(highCount)} · Medium: ${pctOf(medCount)} · Low: ${pctOf(lowCount)} · Informational: ${pctOf(informationalCount)} · Unknown: ${pctOf(unknownCount)} · Unassessed: ${pctOf(unassessedCount)}</div>
  </div>

  <h2>Cryptographic Inventory (${inv.length} findings)</h2>
  <table>
    <thead><tr><th>Finding ID</th><th>Algorithm identity</th><th>Family / identity state</th><th>Variant / role</th><th>Library</th><th>Business criticality</th><th>Key Size</th><th>Final risk / assessment</th><th>Category</th><th>Confidence</th></tr></thead>
    <tbody>
      ${inv.map((item) => `<tr style="${item.risk_assessment_state === "assessed" && item.risk_level === "critical" ? "border-left:4px solid var(--critical)" : ""}">
        <td class="qrypton-technical" style="font-size:var(--type-12);color:var(--text-muted)">${escapeHtml(item.finding_id)}</td>
        <td class="qrypton-technical"><strong>${escapeHtml(item.algorithm_name ?? item.identity_label ?? "Unknown (algorithm not identified)")}</strong></td>
        <td class="qrypton-technical">${escapeHtml(item.algorithm_family ?? item.identity_status ?? "unknown")}</td>
        <td class="qrypton-technical">${escapeHtml([item.algorithm_variant, item.crypto_role].filter(Boolean).join(" · ") || "unknown")}</td>
        <td class="qrypton-technical">${escapeHtml(item.library_name ?? "unknown")}</td>
        <td>${escapeHtml(item.business_criticality ?? "unclassified")}</td>
        <td class="qrypton-technical">${item.key_size_bits ?? "—"}</td>
        <td>${renderToStaticMarkup(<RiskBadge level={item.risk_assessment_state === "unassessed" ? "unassessed" : item.risk_level} />)}</td>
        <td style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(item.category)}</td>
        <td style="">${(item.confidence * 100).toFixed(0)}%</td>
      </tr>`).join("")}
    </tbody>
  </table>

  ${roadmap.length > 0 ? `
  <h2>PQC Migration Roadmap (${roadmap.length} actions)</h2>
  ${roadmap.map((item) => `<div class="roadmap-item"><div class="roadmap-priority">Priority ${escapeHtml(item.priority)}</div><div class="roadmap-action">${escapeHtml(item.action)}</div>${item.target_algorithms && item.target_algorithms.length > 0 ? `<div class="roadmap-algos qrypton-technical">Target: ${escapeHtml(item.target_algorithms.join(", "))}</div>` : ""}</div>`).join("")}` : ""}

  <div class="footer">${REPORT_WORDMARK} Post-Quantum Cryptography Command Center &nbsp;&middot;&nbsp; Report generated ${new Date().toLocaleString()} &nbsp;&middot;&nbsp; NIST FIPS 203/204/205</div>
</body>
</html>`;
      const blob = new Blob([htmlReport], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `qrypton-report-${scanId}-${new Date().toISOString().slice(0, 10)}.html`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setExportNotice("HTML report ready");
    } catch (error) {
      setExportNotice(error instanceof Error ? error.message : "HTML report unavailable; retry this scan");
    } finally {
      setExporting(null);
    }
  };

  // --- Export Handlers ---
  const handleExportCSV = () => {
    setExporting("csv");
    const headers = ["Scan ID", "Timestamp", "Target Type", "Target", "Data origin", "Environment", "Critical", "High", "Medium", "Total Findings", "Status"];
    const rows = scans.map((s) => [
      s.id,
      s.timestamp,
      targetTypeLabel(s.target_type),
      `"${s.target.replace(/"/g, '""')}"`,
      s.sampleData ? "Sample data" : "",
      s.environment,
      s.criticalCount,
      s.highCount,
      s.mediumCount,
      s.totalFindings,
      s.status,
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `qrypton-scan-report-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => setExporting(null), 600);
  };

  const handleExportHTML = async () => {
    setExporting("html");
    let tokenStyles: string;
    try { tokenStyles = await exportTokenStyles(); }
    catch (error) { setExportNotice(error instanceof Error ? error.message : String(error)); setExporting(null); return; }
    const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>QRYPTON PQC Cryptographic Scan Report</title>
  <style>
    ${tokenStyles}
    body { background: var(--background); color: var(--text-primary); padding: 2rem; }
    h1 { color: var(--text-primary); margin-bottom: 0.5rem; }
    p { color: var(--text-muted); font-size: var(--type-12); }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: var(--border); border-radius: 8px; overflow: hidden; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: var(--type-12); }
    th { background: var(--background); color: var(--text-muted); text-transform: none; font-size: var(--type-12); letter-spacing: 0; }
    .critical { color: var(--critical); font-weight: var(--weight-semibold); }
    .badge { padding: 3px 8px; border-radius: 9999px; font-size: var(--type-12); font-weight: 600; background: var(--surface-subtle); color: var(--text-secondary); }
  </style>
</head>
<body>
  <h1>${REPORT_WORDMARK} Cryptographic Posture Scan Report</h1>
  <p>Generated on ${new Date().toLocaleString()} · Post-Quantum Cryptography Command Center</p>
  <table>
    <thead>
      <tr>
        <th>Scan ID</th>
        <th>Timestamp</th>
        <th>Target Type</th>
        <th>Target</th>
        <th>Data origin</th>
        <th>Environment</th>
        <th>Critical</th>
        <th>High</th>
        <th>Total Findings</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      ${scans
        .map(
          (s) => `<tr>
        <td><strong>${escapeHtml(s.id)}</strong></td>
        <td>${escapeHtml(s.timestamp)}</td>
        <td>${escapeHtml(targetTypeLabel(s.target_type))}</td>
        <td class="qrypton-technical">${escapeHtml(s.target)}</td>
        <td>${s.sampleData ? "Sample data" : ""}</td>
        <td>${escapeHtml(s.environment)}</td>
        <td class="critical">${s.criticalCount}</td>
        <td>${s.highCount}</td>
        <td>${s.totalFindings}</td>
        <td><span class="badge">${s.status}</span></td>
      </tr>`
        )
        .join("")}
    </tbody>
  </table>
</body>
</html>`;

    const blob = new Blob([htmlReport], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `qrypton-scan-report-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setTimeout(() => setExporting(null), 600);
  };

  const handleExportPDF = async () => {
    setExporting("pdf");
    // Trigger printable window view formatted for PDF print save
    const printWindow = window.open("", "_blank");
    if (!printWindow) {
      alert("Please allow popups to export PDF");
      setExporting(null);
      return;
    }

    let tokenStyles: string;
    try { tokenStyles = await exportTokenStyles(); }
    catch (error) { printWindow.close(); setExportNotice(error instanceof Error ? error.message : String(error)); setExporting(null); return; }
    printWindow.document.write(`
      <html>
        <head>
          <title>QRYPTON Executive Scan Report</title>
          <style>
    ${tokenStyles}
            body { padding: 24px; color: var(--text-primary); background: var(--background); print-color-adjust: exact; }
            h1 { color: var(--text-primary); }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid var(--border); padding: 10px; text-align: left; font-size: 12px; }
            th { background-color: var(--text-primary); color: var(--background); }
          </style>
        </head>
        <body>
          <h1>${REPORT_WORDMARK} PQC Scan Report</h1>
          <p>Generated: ${new Date().toLocaleString()}</p>
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Timestamp</th>
                <th>Target Type</th>
                <th>Target Artifact</th>
                <th>Environment</th>
                <th>Critical</th>
                <th>Total Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${scans
                .map(
                  (s) => `<tr>
                <td class="qrypton-technical">${s.id}</td>
                <td>${s.timestamp}</td>
                <td>${targetTypeLabel(s.target_type)}</td>
                <td class="qrypton-technical">${s.target}</td>
                <td>${s.environment}</td>
                <td>${s.criticalCount}</td>
                <td>${s.totalFindings}</td>
                <td>${s.status}</td>
              </tr>`
                )
                .join("")}
            </tbody>
          </table>
          <script>
            window.onload = async () => { await document.fonts.ready; window.print(); window.close(); };
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
    setTimeout(() => setExporting(null), 600);
  };

  const quickExportPanel = latestScan && (
    <section aria-label="Latest scan quick export" className="rounded-xl border border-border bg-muted p-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold">Latest Scan — Quick Export</h3>
          <p className="mt-0.5 max-w-xs truncate text-sm font-semibold text-foreground" title={latestScan.target}>{latestScan.target}</p>
          <p className="mt-0.5 text-xs tabular-nums text-muted-foreground">{latestScan.id} &middot; {latestScan.timestamp}</p>
          <div className="mt-1 flex gap-4"><span className="text-xs font-semibold text-secondary">{latestScan.criticalCount} Critical</span><span className="text-xs font-semibold text-secondary">{latestScan.highCount} High</span><span className="text-xs font-semibold text-muted-foreground">{latestScan.totalFindings} Total</span></div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void downloadLatestJson(latestScan.id)} disabled={exporting !== null} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-muted px-4 py-2 text-xs font-semibold text-secondary qrypton-motion hover:bg-muted disabled:opacity-50"><FileCode className="h-3.5 w-3.5" />{exporting === `json-${latestScan.id}` ? "Preparing…" : "Download JSON"}</button>
          <button type="button" onClick={() => void downloadLatestHtml(latestScan.id)} disabled={exporting !== null} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-muted px-4 py-2 text-xs font-semibold text-secondary qrypton-motion hover:bg-muted disabled:opacity-50"><FileText className="h-3.5 w-3.5" />{exporting === `html-${latestScan.id}` ? "Preparing…" : "Download HTML Report"}</button>
          <button type="button" onClick={() => void downloadPdf(latestScan.id)} disabled={exporting !== null} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-muted px-4 py-2 text-xs font-semibold text-secondary qrypton-motion hover:bg-muted disabled:opacity-50"><FileText className="h-3.5 w-3.5" />{exporting === `pdf-${latestScan.id}` ? "Preparing…" : "Download Full PDF Report"}</button>
        </div>
      </div>
      {exportNotice && <p role="status" className="mt-3 text-sm">{exportNotice}</p>}
    </section>
  );

  return (
    <section id="your-scans" aria-labelledby="your-scans-heading" className="space-y-4">
      <Card>
        <CardHeader className="gap-4 border-b border-border p-6 sm:p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle id="your-scans-heading" className="mt-1 flex items-center gap-2 text-xl font-semibold">
                <History className="h-5 w-5 text-secondary" aria-hidden="true" />
                Your Scans
              </CardTitle>
              <p className="mt-1 text-sm text-muted-foreground">
                History of cryptographic assessments executed across your infrastructure.
              </p>
            </div>

            {/* Export Multi-Format Dropdown / Buttons */}
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="secondary"
                onClick={handleExportCSV}
                disabled={exporting !== null}
                className="text-xs font-semibold"
              >
                <FileSpreadsheet className="h-3.5 w-3.5 text-secondary" data-icon="inline-start" />
                Export CSV
              </Button>

              <Button
                variant="secondary"
                onClick={handleExportHTML}
                disabled={exporting !== null}
                className="text-xs font-semibold"
              >
                <FileCode className="h-3.5 w-3.5 text-secondary" data-icon="inline-start" />
                Export HTML
              </Button>

              <Button
                variant="secondary"
                onClick={handleExportPDF}
                disabled={exporting !== null}
                className="text-xs font-semibold"
              >
                <FileText className="h-3.5 w-3.5 text-secondary" data-icon="inline-start" />
                Export PDF
              </Button>
            </div>
          </div>
          {quickExportTarget ? createPortal(quickExportPanel, quickExportTarget) : !quickExportTargetId ? quickExportPanel : null}
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left tabular-nums text-xs">
              <thead className="border-b border-border bg-card/60 text-xs normal-case tracking-normal text-muted-foreground">
                <tr>
                  <th className="px-6 py-4.5 font-semibold">Scan ID</th>
                  <th className="px-6 py-4.5 font-semibold">Timestamp</th>
                  <th className="px-6 py-4.5 font-semibold">Target Type</th>
                  <th className="px-6 py-4.5 font-semibold">Target Artifact</th>
                  <th className="px-6 py-4.5 font-semibold">Environment</th>
                  <th className="px-6 py-4.5 font-semibold">Critical / High</th>
                  <th className="px-6 py-4.5 font-semibold">Total Findings</th>
                  <th className="px-6 py-4.5 text-right font-semibold">Status</th>
                  <th className="px-6 py-4.5 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.length === 0 ? (
                  <tr><td colSpan={9} className="px-6 py-14 text-center font-sans"><p className="font-semibold text-foreground">Your scan history will appear here.</p><p className="mt-1 text-sm text-muted-foreground">Connect a repository, binary, container, or cloud inventory to begin.</p></td></tr>
                ) : scans.map((s) => (
                  <tr
                    data-list-item tabIndex={0}
                    onKeyDown={e => { if (e.target === e.currentTarget && e.key === "Enter") onSelectScan?.(s.id); }}
                    key={s.id}
                    data-risk={s.criticalCount > 0 ? "critical" : undefined}
                    onClick={() => onSelectScan?.(s.id)}
                    className="hover:bg-muted/40 qrypton-motion cursor-pointer group"
                  >
                    <td className="px-6 py-4 font-mono font-semibold text-foreground group-hover:text-secondary qrypton-motion">
                      {s.id}
                    </td>
                    <td className="px-6 py-4 text-muted-foreground whitespace-nowrap">{s.timestamp}</td>
                    <td className="px-6 py-4">
                      <Badge>{targetTypeLabel(s.target_type)}</Badge>
                    </td>
                    <td className="px-6 py-4 text-foreground font-mono font-normal max-w-[260px] truncate" title={s.target}>
                      {s.target} {s.sampleData && <Badge className="ml-2">Sample data</Badge>}
                    </td>
                    <td className="px-6 py-4 text-muted-foreground capitalize">{s.environment}</td>
                    <td className="px-6 py-4">
                      <span className="text-secondary font-semibold">{s.criticalCount}</span>
                      <span className="text-muted-foreground"> / </span>
                      <span className="text-secondary font-semibold">{s.highCount}</span>
                    </td>
                    <td className="px-6 py-4 font-semibold text-foreground">{s.totalFindings}</td>
                    <td className="px-6 py-4 text-right">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${
                        s.status === "FAILED"
                          ? "bg-muted text-secondary border-border"
                          : s.status === "RUNNING"
                            ? "bg-muted text-secondary border-border"
                            : "bg-muted text-secondary border-border"
                      }`}>
                        <CheckCircle2 className="h-3 w-3" />
                        {s.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex min-w-[290px] justify-end gap-2" onClick={(event) => event.stopPropagation()}>
                        <button type="button" onClick={() => onSelectScan?.(s.id)} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><ExternalLink className="size-3" />View</button>
                        <a href={`${API_BASE}/api/v1/scans/${encodeURIComponent(s.id)}/cbom/export?format=json`} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><FileCode className="size-3" />JSON</a>
                        <a href={`${API_BASE}/api/v1/scans/${encodeURIComponent(s.id)}/cbom/export?format=csv`} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><FileSpreadsheet className="size-3" />CSV</a>
                        <button type="button" disabled={exporting === `pdf-${s.id}`} onClick={() => { void downloadPdf(s.id); }} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline disabled:opacity-50"><FileText className="size-3" />{exporting === `pdf-${s.id}` ? "Preparing…" : "PDF"}</button>
                        <button type="button" aria-label={`Delete scan ${s.id}`} onClick={() => { if (window.confirm(`Delete scan ${s.id}? This cannot be undone.`)) onDelete?.(s.id); }} className="text-secondary hover:text-secondary"><Trash2 className="size-3.5" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pageCount > 1 && (
            <nav className="flex items-center justify-center gap-2 border-t border-border p-4" aria-label="Scan history pages">
              <button type="button" onClick={() => onPageChange?.(page - 1)} disabled={page === 0} className="rounded-md border border-border px-2 py-1 text-xs font-semibold disabled:opacity-40">Previous</button>
              {pageNumbers.map((index, position) => <React.Fragment key={index}>{position > 0 && pageNumbers[position - 1] !== index - 1 && <span className="text-muted-foreground">…</span>}<button type="button" onClick={() => onPageChange?.(index)} aria-current={page === index ? "page" : undefined} className={`grid size-8 place-items-center rounded-md text-sm font-semibold qrypton-motion ${page === index ? "bg-primary text-primary-foreground" : "border border-border text-muted-foreground hover:bg-muted"}`}>{index + 1}</button></React.Fragment>)}
              <button type="button" onClick={() => onPageChange?.(page + 1)} disabled={page >= pageCount - 1} className="rounded-md border border-border px-2 py-1 text-xs font-semibold disabled:opacity-40">Next</button>
            </nav>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

export default ScanHistory;
