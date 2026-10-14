import { API_BASE, accessHeaders } from "./api";

export type ReportFormat = "pdf" | "json" | "csv";
export type ReportChoice = ReportFormat | "all" | "none";

export function reportFormats(choice: ReportChoice): ReportFormat[] {
  return choice === "all" ? ["pdf", "json", "csv"] : choice === "none" ? [] : [choice];
}

/** Always use the completed run ID, never the dashboard's current selection. */
export async function downloadScanReport(runId: string, format: ReportFormat): Promise<void> {
  const suffix = format === "pdf" ? "report/pdf" : `cbom/export?format=${format}`;
  const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(runId)}/${suffix}`, {
    headers: accessHeaders(), cache: "no-store", signal: AbortSignal.timeout(60000),
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(typeof detail.detail === "string" ? detail.detail : `${format.toUpperCase()} export failed (HTTP ${response.status})`);
  }
  const blob = await response.blob();
  if (!blob.size) throw new Error("The export was empty. Retry the download.");
  const href = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = href;
    link.download = `qrypton-${format === "pdf" ? "report" : "cbom"}-${runId}.${format === "json" ? "cdx.json" : format}`;
    document.body.appendChild(link); link.click(); link.remove();
  } finally { setTimeout(() => URL.revokeObjectURL(href), 1000); }
}

export async function downloadScanReports(runId: string, choice: ReportChoice): Promise<string> {
  const failed: string[] = [];
  for (const format of reportFormats(choice)) {
    try { await downloadScanReport(runId, format); }
    catch (error) { failed.push(`${format.toUpperCase()}: ${error instanceof Error ? error.message : "Download failed"}`); }
  }
  return failed.length ? `Scan saved. Download issue: ${failed.join("; ")}. Retry from Results → CBOM / Reports.` : choice === "none" ? "" : "Report downloads requested. If blocked, allow downloads for this site or use CBOM / Reports.";
}
