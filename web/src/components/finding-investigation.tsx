"use client";

import { GlossaryText } from "@/components/glossary";
import { useEffect, useRef, type CSSProperties } from "react";
import type { EvidenceRecord, FindingDetailData } from "./finding-detail";
import { RiskBadge } from "./ui/primitives";
import { observed, safeMetadata, timelineGeometry, type Observation } from "@/lib/finding-investigation";

const viewed = new Set<string>();
const years = (value: number | null | undefined) => value == null ? "Unknown" : `${value} years`;

function EvidenceBlock({ evidence, quality }: { evidence: EvidenceRecord; quality?: string }) {
  const viewport = useRef<HTMLPreElement>(null);
  const line = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    // Scroll only the code viewport, preserving the hero and keyboard focus.
    if (viewport.current && line.current) viewport.current.scrollTop = Math.max(0, line.current.offsetTop - viewport.current.offsetTop - 48);
  }, [evidence.id]);
  return <article className="min-w-0 rounded-lg border border-border p-4">
    <p className="mb-3 text-xs font-semibold tracking-wide">{quality === "observed" ? "EVIDENCE · observed" : quality === "inferred" ? "INFERENCE · derived" : "Evidence quality · Unknown"}</p>
    <pre ref={viewport} tabIndex={0} aria-label="Safe evidence location and detection metadata" className="relative max-h-52 overflow-auto rounded-md bg-muted/50 p-4 font-mono text-xs leading-7"><code>
      {`File: ${safeMetadata(evidence.location?.relative_path)}\nDetection method: ${safeMetadata(evidence.kind)}\nScanner: ${safeMetadata(evidence.provenance?.scanner_name)}\nVersion: ${safeMetadata(evidence.provenance?.scanner_version)}\n`}
      <span ref={line} className="investigation-evidence-line block w-fit min-w-full">{`Line ${evidence.location?.line_start ?? "Unknown"}${evidence.location?.line_end && evidence.location.line_end !== evidence.location.line_start ? `–${evidence.location.line_end}` : ""} · API / symbol: ${safeMetadata(evidence.location?.symbol)}`}</span>
      {evidence.kind.includes("manifest") || evidence.kind.includes("metadata") ? "Manifest evidence: recorded at the file location above\n" : ""}
    </code></pre>
    <p className="mt-2 text-xs text-muted-foreground">Metadata view. Source literals, raw excerpts and key material are withheld.</p>
  </article>;
}

export function InvestigationVisuals({ detail }: { detail: FindingDetailData }) {
  const root = useRef<HTMLDivElement>(null);
  const initialized = useRef(false);
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    if (viewed.has(detail.finding.id)) root.current?.setAttribute("data-seen", "true");
    viewed.add(detail.finding.id);
  }, [detail.finding.id]);
  const m = detail.mosca;
  const geometry = timelineGeometry(m);
  const factors = detail.assessment?.factors;
  const context = detail.investigation_context;
  const scanSource = (o?: Observation) => observed(o) !== "Unknown" && o?.basis_evidence_ids?.some(id => detail.evidence_provenance.some(e => e.id === id)) ? "Scan evidence" : "Unknown";
  const contextSource = (o?: Observation) => observed(o) === "Unknown" || !o?.evidence_ids?.length ? "Unknown" : o.evidence_ids.some(id => detail.evidence_provenance.some(e => e.id === id)) ? "Scan evidence" : "User-provided context";
  const steps = [
    { label: "Algorithm weakness", value: observed(factors?.cryptographic_obsolescence), source: scanSource(factors?.cryptographic_obsolescence), note: "Engine factor" },
    { label: "Exposure", value: observed(factors?.quantum_exposure), source: scanSource(factors?.quantum_exposure), note: `Quantum exposure; internet exposure: ${observed(context?.exposure)} (${contextSource(context?.exposure)})` },
    { label: "Data sensitivity", value: observed(context?.data_sensitivity), source: contextSource(context?.data_sensitivity), note: "Business impact input" },
    { label: "Data lifetime", value: years(m?.x_data_lifetime_years), source: m?.x_data_lifetime_years == null || !m?.x_source || m.x_source === "unknown" ? "Unknown" : m.x_source === "scanner" ? "Scan evidence" : "User-provided context", note: `Planning input only · ${m?.x_source ?? "source unknown"}` },
    { label: "Business criticality", value: observed(context?.business_criticality), source: contextSource(context?.business_criticality), note: "Business impact input" },
    { label: "Migration complexity", value: observed(context?.migration_complexity), source: contextSource(context?.migration_complexity), note: "Context only; not scored by this engine" },
  ];
  const unknown = steps.some(step => step.value === "Unknown" || step.source === "Unknown");
  const outcome = m?.mosca_applicable === "no" ? "Not applicable to this cryptographic role" : !geometry ? "Unknown — timeline inputs or persisted result missing" : m!.time_margin_years! < 0 ? "Exposure window — required protection extends beyond the horizon" : m!.time_margin_years === 0 ? "At the planning horizon — no time margin" : "Required protection fits within the planning horizon";
  return <div ref={root} className="investigation-visuals flex min-w-0 flex-col gap-6">
    <section className="rounded-xl border border-border bg-card p-5 sm:p-6" aria-labelledby="mosca-title">
      <div className="flex flex-wrap items-center justify-end gap-3"><RiskBadge level={m?.urgency ?? "unknown"} /></div>
      <h3 id="mosca-title" className="mt-3 text-xl font-semibold">Will Protection Outlast the Planning Horizon?</h3>
      <p className="mt-2 text-sm font-medium">{outcome}</p>
      <div className="mt-5 grid gap-3 text-sm sm:grid-cols-3"><p><strong>X · Confidentiality lifetime</strong><br />{years(m?.x_data_lifetime_years)}</p><p><strong>Y · Migration time</strong><br />{years(m?.y_migration_years)}</p><p><strong><GlossaryText>{"Z · CRQC horizon"}</GlossaryText></strong><br />{years(m?.z_crqc_horizon_years)} · Read-only</p></div>
      {geometry && <div aria-hidden="true" className="relative mb-8 mt-12 h-24 border-b border-border">
        <div className="absolute top-5 flex h-9 w-full"><div className="h-full rounded-l qrypton-timeline-x" style={{ width: `${geometry.x}%` }} /><div className="h-full rounded-r border-2 border-dashed border-pqc qrypton-timeline-y" style={{ width: `${geometry.y}%` }} /></div>
        <div className="absolute -top-5 bottom-0 z-20 qrypton-threshold border-l-2 border-primary" style={{ left: `${geometry.z}%` }}><span className="absolute -top-2 -translate-x-1/2 whitespace-nowrap rounded bg-background px-2 text-xs font-semibold">Z · {m?.z_crqc_horizon_years}y</span></div>
        {geometry.overflow > 0 && <div className="investigation-overflow absolute top-5 h-9 border-l-2 border-dashed border-foreground" style={{ left: `${geometry.z}%`, width: `${geometry.overflow}%`, background: "var(--critical)" }} />}
        <span className="absolute -bottom-6 left-0 text-xs">0 · Now</span><span className="absolute bottom-1 left-0 text-xs">{geometry.overflow > 0 ? "Exposure window" : "X + Y"} · Required protection: {years(m?.required_security_years)}</span>
      </div>}
      <p className="sr-only">X: {years(m?.x_data_lifetime_years)}. Y: {years(m?.y_migration_years)}. Z: {years(m?.z_crqc_horizon_years)}. {outcome}. Time margin: {years(m?.time_margin_years)}.</p>
      <p className="mt-4 text-xs text-muted-foreground">Persisted time margin: {years(m?.time_margin_years)}. The selected scenario horizon is read-only in this view.</p>
      <p className="mt-3 text-xs font-medium">Planning heuristic, not a prediction of quantum computer arrival.</p>
    </section>

    <section aria-labelledby="risk-build-title" className="rounded-xl border border-border p-5 sm:p-6">
      <h3 id="risk-build-title" className="text-lg font-semibold">From Evidence to the Final Tier</h3>
      <p className="mt-2 text-sm text-muted-foreground">The engine uses categorical rules, not additive weights. Values below are recorded inputs and factors; step heights do not represent score contributions.</p>
      <ol className="mt-5 grid gap-2 sm:grid-cols-3">{steps.map((step, index) => <li key={step.label} className="investigation-step relative rounded-md border border-border bg-muted/20 p-3" style={{ "--step-delay": `${index * 100}ms` } as CSSProperties}>
        <p className="text-xs text-muted-foreground">{index + 1} / {step.label}</p><p className="my-2 font-sans tabular-nums text-xl font-semibold">{step.value}</p><p className="text-xs font-medium">Source: {step.source}</p><p className="mt-2 text-xs text-muted-foreground">{step.note}</p>
      </li>)}</ol>
      <div className="investigation-final mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted p-4"><div className="relative min-h-16 min-w-48">
        <div className="investigation-score-final"><p className="text-xs text-muted-foreground">Final engine score</p><p className="font-sans tabular-nums text-3xl font-semibold">{observed(detail.assessment?.score)}</p></div>
        {steps.map((step, index) => <div key={step.label} aria-hidden="true" className="investigation-score-tick absolute inset-0 bg-background" style={{ "--step-delay": `${index * 100}ms` } as CSSProperties}><p className="text-xs text-muted-foreground">{step.label}</p><p className="font-sans tabular-nums text-2xl font-semibold">{step.value}</p></div>)}
      </div><RiskBadge level={detail.assessment?.final_priority ?? detail.assessment?.level ?? "unknown"} /></div>
      <p className="mt-3 text-sm text-muted-foreground">{unknown ? "Limited confidence in the explanation: unknown factors or sources remain." : "All six inputs have recorded values and sources."} Engine evidence confidence: {factors?.evidence_confidence ?? "Unknown"}.</p>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted-foreground">{factors?.rationale?.map((reason, index) => <li key={index}>{reason}</li>)}</ul>
    </section>

    <section aria-labelledby="evidence-title" className="flex flex-col gap-3"><h3 id="evidence-title" className="text-lg font-semibold">Inspect the Basis of This Finding</h3>
      {detail.evidence_provenance.length ? detail.evidence_provenance.map(e => <EvidenceBlock key={e.id} evidence={e} quality={detail.evidence_quality?.[e.id]} />) : <p className="text-sm text-muted-foreground">Unknown — no evidence records were returned.</p>}
      <aside className="rounded-lg border border-dashed border-border p-4"><p className="text-xs font-semibold">INFERENCE · derived</p><p className="mt-2 text-sm text-muted-foreground">Risk tiers, timeline urgency and recommendations are derived assessments. {detail.evidence_authenticity?.summary ?? "Evidence authenticity is unknown."}</p></aside>
    </section>
  </div>;
}
