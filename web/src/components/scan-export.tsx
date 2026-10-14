"use client";

import { useEffect, useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { workspaceRequest } from "@/lib/api";

import { downloadScanReport } from "@/lib/scan-download";

type ExportPreview = {
  run_id: string; scope: string; target_type: string; asset_count: number; finding_count: number;
  risk_summary: Record<string, number>; cbom_available: boolean; report_available: boolean; provenance: string;
};
type ExportFormat = "json" | "csv" | "pdf";

export function ScanExport({ runId }: { runId: string | null }) {
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState<ExportFormat | null>(null);
  const [success, setSuccess] = useState<ExportFormat | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!runId) return;
    const controller = new AbortController();
    queueMicrotask(() => { if (!controller.signal.aborted) { setLoading(true); setPreview(null); setSuccess(null); setError(""); } });
    workspaceRequest<ExportPreview>(`/scans/${encodeURIComponent(runId)}/export-preview`, { signal: controller.signal })
      .then(setPreview)
      .catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Export preview unavailable"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [runId]);

  const download = async (format: ExportFormat) => {
    if (!runId || !preview) return;
    setGenerating(format); setSuccess(null); setError("");
    try {
      await downloadScanReport(runId, format);
      setSuccess(format);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed; retry this scan");
    } finally { setGenerating(null); }
  };

  if (!runId) return <p role="status" className="mt-4 rounded border border-border p-4 text-sm">No completed scan selected. Run or select a completed scan to export its CBOM or report.</p>;
  return <div className="mt-4 rounded-lg border border-border p-4" aria-label="Scan export">
    {loading && <p role="status" className="text-sm">Loading export scope and risk summary…</p>}
    {preview && <>
      <p className="font-semibold">Review export · {preview.scope}</p>
      <p className="mt-1 text-sm">Scope: {preview.target_type} · {preview.asset_count} asset{preview.asset_count === 1 ? "" : "s"} · {preview.finding_count} findings</p>
      <p className="mt-1 text-sm">Risk: {Object.entries(preview.risk_summary).map(([level, count]) => `${count} ${level}`).join(" · ")}</p>
      <p className="mt-1 text-xs text-muted-foreground">{preview.provenance}. Uncertain observations retain their recorded state.</p>
      {preview.finding_count === 0 && <p role="status" className="mt-2 text-sm">This scan has no findings; the export will contain the asset scope and an empty finding inventory.</p>}
      <div className="mt-3 flex flex-wrap gap-2">
        {(["json", "csv", "pdf"] as const).map(format => <button key={format} type="button" disabled={!!generating || (format === "pdf" ? !preview.report_available : !preview.cbom_available)} onClick={() => void download(format)} className="inline-flex items-center gap-2 rounded border border-border px-3 py-2 text-sm disabled:opacity-50">
          {generating === format ? <Loader2 className="size-4" /> : <Download className="size-4" />}
          {generating === format ? "Generating…" : format === "pdf" ? "Report PDF" : `CBOM ${format.toUpperCase()}`}
        </button>)}
      </div>
      {!preview.cbom_available && <p className="mt-2 text-sm">No persisted CBOM is available for this scan. Choose another completed scan.</p>}
      {success && <p role="status" className="mt-3 inline-flex items-center gap-2 rounded-full border border-safe bg-safe-tint px-3 py-1 text-sm text-safe"><svg className="export-check size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" aria-hidden="true"><path d="m4 12 5 5L20 6" /></svg>{success.toUpperCase()} ready</p>}
    </>}
    {error && <p role="alert" className="mt-3 rounded border border-destructive p-3 text-sm">{error}. Check the selected scan and retry.</p>}
  </div>;
}
