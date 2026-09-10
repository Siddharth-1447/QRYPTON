"use client";

import { AlertTriangle, Check, Code2, Copy, Info, Loader2, X } from "lucide-react";
import { Alert, Badge, Button, Card, CardContent, CardHeader, CardTitle } from "@/components/ui/primitives";

type ObservationValue = { state?: string; value?: unknown; rationale?: string | null };
type FindingDetailData = {
  finding: { id: string; category: string; confidence: number; first_observed_at: string; last_observed_at: string; function?: unknown; protocol?: unknown; algorithm?: { value?: { canonical_name?: unknown; family?: unknown; key_size_bits?: ObservationValue; lifecycle_status?: unknown; parameters?: unknown } }; provenance?: { scanner_name?: string; scanner_version?: string; observed_at?: string } };
  assessment?: { score?: ObservationValue; level?: string; factors?: { rationale?: unknown[]; cryptographic_obsolescence?: ObservationValue; quantum_exposure?: ObservationValue; exploitability?: ObservationValue; business_impact?: ObservationValue } } | null;
  evidence_provenance: Array<{ id: string; kind: string; confidence: number; location?: { relative_path?: string; line_start?: number; line_end?: number; symbol?: string }; excerpt?: string }>;
  recommendations: Array<{ id: string; priority: number; title: string; action: string; nist_references?: string[]; replacement_algorithm?: { value?: { canonical_name?: string } } }>;
};

type Props = { open: boolean; loading: boolean; detail: FindingDetailData | null; onClose: () => void; copiedId: string | null; onCopy: (id: string, label: string) => void };

function Metric({ label, value }: { label: string; value: string }) { return <div className="flex flex-col gap-1 rounded-md border border-border bg-muted/30 p-3"><span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</span><span className="font-mono text-sm font-semibold text-foreground">{value}</span></div>; }

function displayValue(value: unknown, fallback = "Unknown / Not observed"): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (value && typeof value === "object" && "value" in value) return displayValue((value as ObservationValue).value, fallback);
  return fallback;
}

function numericObservation(value: ObservationValue | undefined): number | null {
  return typeof value?.value === "number" ? value.value : null;
}

export function FindingDetail({ open, loading, detail, onClose, copiedId, onCopy }: Props) {
  if (!open) return null;
  const finding = detail?.finding;
  const algorithm = finding?.algorithm?.value;
  const score = numericObservation(detail?.assessment?.score);
  const level = detail?.assessment?.level ?? "unassessed";
  const exposure = numericObservation(detail?.assessment?.factors?.quantum_exposure);
  const rationale = (detail?.assessment?.factors?.rationale ?? []).map((item) => displayValue(item, "")).filter(Boolean);
  const riskReasons = [
    ...rationale,
    exposure != null ? `Quantum-planning exposure is ${exposure.toFixed(1)}/100, based on the persisted Mosca timeline inputs.` : "Quantum exposure could not be calculated from the available scan context.",
    algorithm?.canonical_name ? `${displayValue(algorithm.canonical_name)} is the algorithm observed in this finding; its risk is evaluated together with the asset's business context and migration timeline.` : "The algorithm could not be identified, so validation is required before a migration target is selected.",
  ];
  return <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-labelledby="finding-detail-title">
    <button type="button" aria-label="Close finding detail" onClick={onClose} className="absolute inset-0 bg-foreground/20 backdrop-blur-[2px]" />
    <aside className="relative flex h-full w-full max-w-3xl flex-col overflow-y-auto border-l border-border bg-background shadow-2xl">
      <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-border bg-background/95 p-5 backdrop-blur sm:p-6"><div><p className="qrypton-kicker">Investigation workspace</p><h2 id="finding-detail-title" className="mt-1 text-xl font-semibold tracking-tight">Why this is risky</h2><p className="mt-1 text-sm text-muted-foreground">Finding evidence, context, urgency, and the next migration decision in one view.</p></div><Button variant="ghost" onClick={onClose} aria-label="Close"><X data-icon="inline-start" /></Button></header>
      <div className="flex flex-col gap-5 p-5 sm:p-6">
        {loading && <div className="flex min-h-64 flex-col items-center justify-center gap-3 text-sm text-muted-foreground"><Loader2 className="animate-spin text-primary" />Loading finding evidence and risk factors…</div>}
        {!loading && !detail && <Alert className="border-destructive/30"><AlertTriangle className="text-destructive" /><div><p className="font-semibold">Finding details unavailable</p><p className="mt-1 text-muted-foreground">The detail service did not return this finding. Close the workspace and retry from the inventory.</p></div></Alert>}
        {!loading && detail && <>
          <Card className="border-primary/20 bg-primary/[0.03]"><CardHeader className="gap-3"><div className="flex flex-wrap items-center gap-2"><Badge tone={level === "critical" ? "critical" : level === "high" ? "high" : "medium"}>{level} risk</Badge><span className="text-xs text-muted-foreground">{finding?.category.replaceAll("_", " ")}</span></div><CardTitle className="text-lg">{displayValue(algorithm?.canonical_name, "Unknown cryptographic algorithm")}</CardTitle><p className="max-w-2xl text-sm leading-6 text-muted-foreground">{rationale[0] ?? "This cryptographic asset requires review because its algorithm, context, or migration timeline increases quantum exposure."}</p><div className="flex flex-wrap items-center gap-2"><code className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">{finding?.id}</code><Button variant="secondary" onClick={() => onCopy(finding?.id ?? "", "finding-id")}>{copiedId === "finding-id" ? <><Check data-icon="inline-start" />Copied</> : <><Copy data-icon="inline-start" />Copy ID</>}</Button></div></CardHeader></Card>
          <section className="rounded-md border border-amber-500/30 bg-amber-500/[0.06] p-4"><p className="qrypton-kicker">Risk explanation</p><h3 className="mt-1 text-base font-semibold">Why this needs attention</h3><ul className="mt-3 space-y-2 text-sm leading-6 text-muted-foreground">{riskReasons.map((reason, index) => <li key={`${index}-${reason}`} className="flex gap-2"><span className="text-amber-500">•</span><span>{reason}</span></li>)}</ul></section>
          <section className="flex flex-col gap-3"><div><p className="qrypton-kicker">Finding summary</p><h3 className="mt-1 text-base font-semibold">Risk in operational terms</h3></div><div className="grid gap-3 sm:grid-cols-3"><Metric label="Risk score" value={score == null ? "Not assessed" : `${score}/100`} /><Metric label="Confidence" value={`${Math.round((finding?.confidence ?? 0) * 100)}%`} /><Metric label="First / last observed" value={`${finding?.first_observed_at?.slice(0, 10) ?? "Unknown"} / ${finding?.last_observed_at?.slice(0, 10) ?? "Unknown"}`} /></div><div className="grid gap-3 sm:grid-cols-2"><Metric label="Canonical algorithm" value={displayValue(algorithm?.canonical_name)} /><Metric label="Family" value={displayValue(algorithm?.family)} /><Metric label="Function" value={displayValue(finding?.function ?? finding?.category)} /><Metric label="Parameters" value={algorithm?.parameters ? displayValue(algorithm.parameters) : algorithm?.key_size_bits?.value ? `${displayValue(algorithm.key_size_bits.value)} bits` : "Unknown / Not observed"} /><Metric label="Protocol" value={displayValue(finding?.protocol)} /><Metric label="Lifecycle" value={displayValue(algorithm?.lifecycle_status)} /></div></section>
          <Alert className="border-amber-500/30 bg-amber-500/[0.06]"><Info className="text-amber-600" /><div><p className="font-semibold">Mosca urgency is a planning heuristic</p><p className="mt-1 leading-6 text-muted-foreground">X + Y &gt; Z helps prioritize migration where data lifetime plus migration time may exceed an assumed CRQC horizon. It is not an exact forecast of when a cryptographically relevant quantum computer will exist.</p></div></Alert>
          <section className="flex flex-col gap-3"><div><p className="qrypton-kicker">Traceable evidence</p><h3 className="mt-1 text-base font-semibold">Observed evidence, not inferred context</h3></div>{detail.evidence_provenance.length ? detail.evidence_provenance.map((evidence, index) => <Card key={`${evidence.id || 'evidence'}-${index}`}><CardContent className="flex flex-col gap-3 pt-5"><div className="flex flex-wrap items-center justify-between gap-2 text-xs"><span className="font-mono font-semibold text-primary">Observed: {evidence.location?.relative_path ?? evidence.kind}</span><span className="text-muted-foreground">{evidence.location?.line_start ? `Lines ${evidence.location.line_start}–${evidence.location.line_end ?? evidence.location.line_start}` : "Binary / layer metadata"} · {Math.round(evidence.confidence * 100)}% confidence</span></div>{evidence.location?.symbol && <p className="text-xs text-muted-foreground">Observed symbol/API string: {evidence.location.symbol}</p>}{evidence.excerpt && <pre className="overflow-x-auto rounded-md border border-border bg-muted/50 p-3 text-xs leading-5 text-foreground"><code>{evidence.excerpt}</code></pre>}<p className="text-xs text-muted-foreground">Inference: risk and migration guidance are calculated from this evidence plus declared business context.</p></CardContent></Card>) : <p className="text-sm text-muted-foreground">No source excerpt was returned; provenance is Unknown / Not observed.</p>}</section>
          <section className="flex flex-col gap-3"><div><p className="qrypton-kicker">Recommended action</p><h3 className="mt-1 text-base font-semibold">PQC or hybrid migration path</h3></div>{detail.recommendations.length ? detail.recommendations.map((rec, index) => <Card key={`${rec.id || 'rec'}-${index}`} className="border-success/30 bg-success/[0.04]"><CardContent className="flex flex-col gap-2 pt-5"><div className="flex items-start justify-between gap-3"><p className="font-semibold">{rec.title}</p><Badge tone="success">Priority {rec.priority}</Badge></div><p className="text-sm leading-6 text-muted-foreground">{rec.action}</p>{rec.replacement_algorithm?.value?.canonical_name && <p className="text-xs text-muted-foreground">Target: <strong className="text-foreground">{rec.replacement_algorithm.value.canonical_name}</strong></p>}{rec.nist_references?.length ? <p className="text-xs text-muted-foreground">References: {rec.nist_references.join(", ")}</p> : null}</CardContent></Card>) : <p className="text-sm text-muted-foreground">No migration recommendation was returned for this finding.</p>}</section>
          <Card><CardHeader><CardTitle className="flex items-center gap-2"><Code2 className="text-primary" />Provenance</CardTitle></CardHeader><CardContent className="grid gap-3 text-sm sm:grid-cols-2"><Metric label="Scanner" value={finding?.provenance?.scanner_name ?? "QRYPTON scanner"} /><Metric label="Scanner version" value={finding?.provenance?.scanner_version ?? "Not reported"} /></CardContent></Card>
        </>}
      </div>
    </aside>
  </div>;
}

export default FindingDetail;
