"use client";

import React, { useState } from "react";
import { History, FileSpreadsheet, FileCode, FileText, CheckCircle2, Trash2, ExternalLink } from "lucide-react";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from "@/components/ui/primitives";

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
  onSelectScan?: (scanId: string) => void;
  onDelete?: (scanId: string) => void;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

export function ScanHistory({ scans = DEFAULT_SCANS, onSelectScan, onDelete }: ScanHistoryProps) {
  const [exporting, setExporting] = useState<string | null>(null);

  const downloadPdf = async (scanId: string) => {
    setExporting(`pdf-${scanId}`);
    try {
      const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(scanId)}/report/pdf`);
      if (!response.ok) throw new Error("Report generation failed");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `qrypton-executive-report-${scanId}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } finally {
      setExporting(null);
    }
  };

  // --- Export Handlers ---
  const handleExportCSV = () => {
    setExporting("csv");
    const headers = ["Scan ID", "Timestamp", "Target Type", "Target", "Environment", "Critical", "High", "Medium", "Total Findings", "Status"];
    const rows = scans.map((s) => [
      s.id,
      s.timestamp,
      targetTypeLabel(s.target_type),
      `"${s.target.replace(/"/g, '""')}"`,
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

  const handleExportHTML = () => {
    setExporting("html");
    const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>QRYPTON PQC Cryptographic Scan Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
    h1 { color: #10b981; margin-bottom: 0.5rem; }
    p { color: #94a3b8; font-size: 0.9rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: #1e293b; border-radius: 8px; overflow: hidden; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.85rem; }
    th { background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
    .critical { color: #ef4444; font-weight: bold; }
    .badge { padding: 3px 8px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; background: rgba(16, 185, 129, 0.2); color: #34d399; }
  </style>
</head>
<body>
  <h1>QRYPTON Cryptographic Posture Scan Report</h1>
  <p>Generated on ${new Date().toLocaleString()} · Post-Quantum Cryptography Command Center</p>
  <table>
    <thead>
      <tr>
        <th>Scan ID</th>
        <th>Timestamp</th>
        <th>Target Type</th>
        <th>Target</th>
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
        <td><strong>${s.id}</strong></td>
        <td>${s.timestamp}</td>
        <td>${targetTypeLabel(s.target_type)}</td>
        <td>${s.target}</td>
        <td>${s.environment}</td>
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

  const handleExportPDF = () => {
    setExporting("pdf");
    // Trigger printable window view formatted for PDF print save
    const printWindow = window.open("", "_blank");
    if (!printWindow) {
      alert("Please allow popups to export PDF");
      setExporting(null);
      return;
    }

    printWindow.document.write(`
      <html>
        <head>
          <title>QRYPTON Executive Scan Report</title>
          <style>
            body { font-family: sans-serif; padding: 20px; color: #1e293b; }
            h1 { color: #059669; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; font-size: 12px; }
            th { background-color: #f1f5f9; }
          </style>
        </head>
        <body>
          <h1>QRYPTON PQC Scan Report</h1>
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
                <td>${s.id}</td>
                <td>${s.timestamp}</td>
                <td>${targetTypeLabel(s.target_type)}</td>
                <td>${s.target}</td>
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
            window.onload = () => { window.print(); window.close(); };
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
    setTimeout(() => setExporting(null), 600);
  };

  return (
    <section id="scans" aria-labelledby="your-scans-heading" className="space-y-4">
      <Card>
        <CardHeader className="gap-4 border-b border-border p-5 sm:p-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="qrypton-kicker">Execution Audit Trail</p>
              <CardTitle id="your-scans-heading" className="mt-1 flex items-center gap-2 text-xl font-semibold">
                <History className="h-5 w-5 text-emerald-400" aria-hidden="true" />
                YOUR SCANS
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
                <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" data-icon="inline-start" />
                Export CSV
              </Button>

              <Button
                variant="secondary"
                onClick={handleExportHTML}
                disabled={exporting !== null}
                className="text-xs font-semibold"
              >
                <FileCode className="h-3.5 w-3.5 text-cyan-400" data-icon="inline-start" />
                Export HTML
              </Button>

              <Button
                variant="secondary"
                onClick={handleExportPDF}
                disabled={exporting !== null}
                className="text-xs font-semibold"
              >
                <FileText className="h-3.5 w-3.5 text-purple-400" data-icon="inline-start" />
                Export PDF
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="border-b border-border bg-card/60 text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-5 py-3.5 font-semibold">Scan ID</th>
                  <th className="px-5 py-3.5 font-semibold">Timestamp</th>
                  <th className="px-5 py-3.5 font-semibold">Target Type</th>
                  <th className="px-5 py-3.5 font-semibold">Target Artifact</th>
                  <th className="px-5 py-3.5 font-semibold">Environment</th>
                  <th className="px-5 py-3.5 font-semibold">Critical / High</th>
                  <th className="px-5 py-3.5 font-semibold">Total Findings</th>
                  <th className="px-5 py-3.5 text-right font-semibold">Status</th>
                  <th className="px-5 py-3.5 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.length === 0 ? (
                  <tr><td colSpan={9} className="px-5 py-14 text-center font-sans"><p className="font-semibold text-foreground">Your scan history will appear here.</p><p className="mt-1 text-sm text-muted-foreground">Connect a repository, binary, container, or cloud inventory to begin.</p></td></tr>
                ) : scans.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => onSelectScan?.(s.id)}
                    className="hover:bg-muted/40 transition-colors cursor-pointer group"
                  >
                    <td className="px-5 py-4 font-bold text-foreground group-hover:text-emerald-400 transition-colors">
                      {s.id}
                    </td>
                    <td className="px-5 py-4 text-muted-foreground whitespace-nowrap">{s.timestamp}</td>
                    <td className="px-5 py-4">
                      <Badge tone="info">{targetTypeLabel(s.target_type)}</Badge>
                    </td>
                    <td className="px-5 py-4 text-foreground font-sans font-medium max-w-[260px] truncate" title={s.target}>
                      {s.target}
                    </td>
                    <td className="px-5 py-4 text-muted-foreground capitalize">{s.environment}</td>
                    <td className="px-5 py-4">
                      <span className="text-rose-400 font-bold">{s.criticalCount}</span>
                      <span className="text-muted-foreground"> / </span>
                      <span className="text-amber-400 font-bold">{s.highCount}</span>
                    </td>
                    <td className="px-5 py-4 font-bold text-foreground">{s.totalFindings}</td>
                    <td className="px-5 py-4 text-right">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border ${
                        s.status === "FAILED"
                          ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                          : s.status === "RUNNING"
                            ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                            : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                      }`}>
                        <CheckCircle2 className="h-3 w-3" />
                        {s.status}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex min-w-[290px] justify-end gap-2" onClick={(event) => event.stopPropagation()}>
                        <button type="button" onClick={() => onSelectScan?.(s.id)} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><ExternalLink className="size-3" />View</button>
                        <a href={`${API_BASE}/api/v1/scans/${encodeURIComponent(s.id)}/cbom/export?format=json`} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><FileCode className="size-3" />JSON</a>
                        <a href={`${API_BASE}/api/v1/scans/${encodeURIComponent(s.id)}/cbom/export?format=csv`} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"><FileSpreadsheet className="size-3" />CSV</a>
                        <button type="button" disabled={exporting === `pdf-${s.id}`} onClick={() => { void downloadPdf(s.id); }} className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline disabled:opacity-50"><FileText className="size-3" />{exporting === `pdf-${s.id}` ? "Preparing…" : "PDF"}</button>
                        <button type="button" aria-label={`Delete scan ${s.id}`} onClick={() => { if (window.confirm(`Delete scan ${s.id}? This cannot be undone.`)) onDelete?.(s.id); }} className="text-rose-400 hover:text-rose-300"><Trash2 className="size-3.5" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

export default ScanHistory;
