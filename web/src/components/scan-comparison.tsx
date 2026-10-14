"use client";
import { GlossaryText } from "./glossary";
import { useEffect, useState } from "react";
import { workspaceRequest } from "@/lib/api";
import type { ScanHistoryRecord } from "./scan-history";
import { Info } from "lucide-react";

type Choice = { id: string; asset_id: string; target: string; timestamp: string };
type Row = { finding_id: string; before: { identity_label: string; risk_score: number | null } | null; after: { identity_label: string; risk_score: number | null } | null; changed_fields: string[] };
type Comparison = { categories: Record<string, Row[]>; risk_before: number; risk_after: number; risk_measure: string; unscored: number[] };
function RiskCounter({ before, after }: { before: number; after: number }) {
  const [value, setValue] = useState(before);
  useEffect(() => {
    let frame = 0;
    const start = performance.now();
    const media = matchMedia("(prefers-reduced-motion: reduce)");
    const reduced = media.matches;
    const settle = () => { if (media.matches) { cancelAnimationFrame(frame); setValue(after); } };
    media.addEventListener("change", settle);
    const tick = (now: number) => { const t = reduced ? 1 : Math.min(1, (now - start) / 500); setValue(before + (after - before) * t); if (t < 1) frame = requestAnimationFrame(tick); };
    frame = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(frame); media.removeEventListener("change", settle); };
  }, [before, after]);
  return <span className="text-3xl font-semibold tabular-nums" aria-label={`Risk total ${before.toFixed(1)} to ${after.toFixed(1)}`}><span aria-hidden="true">{value.toFixed(1)}</span></span>;
}
export function ScanComparison({ scans, backView = "" }: { scans: ScanHistoryRecord[]; backView?: string }) {
  const [available, setAvailable] = useState<Choice[]>([]);
  const [before, setBefore] = useState(""); const [after, setAfter] = useState("");
  const [data, setData] = useState<Comparison | null>(null); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true); const [historyError, setHistoryError] = useState("");
  const [showInfo, setShowInfo] = useState(false);
  const [reload, setReload] = useState(0);
  const scanRevision = scans.map(scan => `${scan.id}:${scan.status}`).join("|");
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => { if (!controller.signal.aborted) { setHistoryLoading(true); setHistoryError(""); } });
    void workspaceRequest<Choice[]>("/scan-comparison/options", { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) }).then(rows => {
      if (controller.signal.aborted) return;
      const ordered = [...rows].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
      setAvailable(ordered); setData(null);
      const current = ordered.find(scan => ordered.some(other => other.id !== scan.id && other.asset_id === scan.asset_id && Date.parse(other.timestamp) <= Date.parse(scan.timestamp)));
      const baseline = current && ordered.find(scan => scan.id !== current.id && scan.asset_id === current.asset_id && Date.parse(scan.timestamp) <= Date.parse(current.timestamp));
      setBefore(baseline?.id ?? ""); setAfter(current?.id ?? "");
    }).catch(() => { if (!controller.signal.aborted) setHistoryError("Could not load scan choices. Check the backend connection and retry."); })
      .finally(() => { if (!controller.signal.aborted) setHistoryLoading(false); });
    return () => controller.abort();
  }, [scanRevision, reload]);
  const baseline = available.find(scan => scan.id === before);
  const currentChoices = available.filter(scan => baseline && scan.id !== before && scan.asset_id === baseline.asset_id && Date.parse(scan.timestamp) >= Date.parse(baseline.timestamp));
  const compare = async () => {
    setBusy(true); setError(""); setData(null);
    try { setData(await workspaceRequest<Comparison>(`/scan-comparison?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`)); }
    catch (e) { setError(e instanceof Error ? e.message : "Comparison unavailable"); } finally { setBusy(false); }
  };
  return <section id="scan-comparison" className="qrypton-card p-6" aria-label="Scan comparison">
    <div className="flex items-center gap-2"><h2 className="text-xl font-semibold">Progress Between Scans</h2><button type="button" aria-label="About scan comparison" aria-expanded={showInfo} aria-controls="comparison-help" onClick={() => setShowInfo(!showInfo)} className="rounded p-1 text-muted-foreground hover:text-primary"><Info className="size-4" /></button></div>{showInfo && <div id="comparison-help" className="my-3 rounded border border-border bg-muted p-4 text-sm">Choose an earlier baseline and a later completed scan of the same application. New findings appeared in the later scan; Resolved findings are absent from its scope; Changed findings have different recorded properties; Persistent findings remain unchanged. Risk totals sum recorded scores, excluding unscored findings. Changes in scope or assumptions can change totals without remediation. Only the latest 500 completed scans are listed; partial scans are excluded to avoid false resolutions.</div>}<p className="my-2 text-sm text-muted-foreground">Compare completed scans of the same application. Scores use each scan’s recorded assumptions.</p>
    {historyLoading && <div role="status" aria-label="Loading Scan choices" className="mb-3 flex flex-wrap gap-3"><span className="sr-only">Loading Scan choices…</span><div aria-hidden="true" className="h-10 w-64 rounded bg-muted" /><div aria-hidden="true" className="h-10 w-64 rounded bg-muted" /></div>}
    {historyError && <p role="alert" className="mb-3 rounded border border-border bg-muted p-3 text-sm text-foreground">{historyError} <button className="text-primary underline" onClick={() => setReload(reload + 1)}>Retry</button></p>}
    {!historyLoading && available.length < 2 && <p role="status" className="mb-3 text-sm text-muted-foreground">Two completed Scans are needed for comparison. Complete another Scan to see what changed.</p>}
    <form onSubmit={e => { e.preventDefault(); void compare(); }} className="flex flex-wrap items-end gap-3">{([["Baseline", before, setBefore], ["Current", after, setAfter]] as const).map(([label, value, change]) => <label key={label} className="text-sm">{label}<select aria-label={label} required disabled={busy || historyLoading} value={value} onChange={e => { change(e.target.value); setData(null); setError(""); if (label === "Baseline") setAfter(""); }} className="block max-w-80 rounded border border-border bg-background p-2"><option value="">Select scan</option>{(label === "Baseline" ? available : currentChoices).map(s => <option key={s.id} value={s.id}>{s.timestamp.slice(0, 23).replace("T", " ")} · {s.id.slice(-6)} · {s.target}</option>)}</select></label>)}<button disabled={busy || !before || !after || before === after} className="rounded bg-primary px-4 py-2 text-primary-foreground disabled:opacity-50">{busy ? "Comparing…" : "Compare scans"}</button></form>
    {before && !currentChoices.length && !historyLoading && <p className="mt-3 text-sm text-muted-foreground">No later completed scan exists for this application. Choose an earlier baseline or run another scan.</p>}
    {error && <p role="alert" className="mt-3 text-destructive">{error}</p>}
    {data && <div className="mt-5"><RiskCounter before={data.risk_before} after={data.risk_after} /><p className="text-sm">{data.risk_measure} · Change {(data.risk_after - data.risk_before).toFixed(1)}</p><p className="text-xs text-muted-foreground">Unscored findings: {data.unscored[0]} → {data.unscored[1]}. Resolved means absent from the later scan’s scope.</p><div className="mt-4 grid gap-4 md:grid-cols-2">{Object.entries(data.categories).map(([category, rows]) => <section key={category} className="rounded border border-border p-4"><h3 className="font-semibold">{category} <span className="tabular-nums">{rows.length}</span></h3><ul className="mt-2 space-y-2">{rows.map(row => <li key={row.finding_id} className={category === "Resolved" ? "finding-resolved" : category === "New" ? "finding-new" : ""}><a data-list-item data-status-target className="text-sm text-primary underline-offset-4 hover:underline" href={`/finding?run_id=${encodeURIComponent(row.after ? after : before)}&finding_id=${encodeURIComponent(row.finding_id)}&view=${encodeURIComponent(backView)}`}><GlossaryText>{(row.after ?? row.before)?.identity_label ?? "Unknown finding"}</GlossaryText></a><p className="text-xs text-muted-foreground">{row.finding_id.slice(-10)} · {row.before?.risk_score ?? "—"} → {row.after?.risk_score ?? "—"}{row.changed_fields.length > 0 && ` · ${row.changed_fields.join(", ").replaceAll("_", " ")}`}</p></li>)}</ul>{!rows.length && <p className="text-sm text-muted-foreground">No findings</p>}</section>)}</div></div>}
  </section>;
}
