"use client";

import { GlossaryText } from "@/components/glossary";
import { useEffect, useRef } from "react";
import Link from "next/link";
import { Check, Copy, Info, X } from "lucide-react";
import { Alert, Badge, RiskBadge, Button, Card, CardContent } from "@/components/ui/primitives";
import { FindingStatus } from "@/components/finding-status";
import { FindingTicket } from "@/components/finding-ticket";
import { InvestigationVisuals } from "@/components/finding-investigation";
import { applicationHref, safeMetadata, type Observation, type Timeline } from "@/lib/finding-investigation";

type ObservationValue<T = unknown> = Observation & { value?: T };
export type EvidenceRecord = {
  id: string; kind: string; confidence: number;
  attributes?: Record<string, string | number | boolean | null>;
  provenance?: { scanner_name?: string; scanner_version?: string };
  location?: { relative_path?: string; line_start?: number; line_end?: number; byte_start?: number; byte_end?: number; symbol?: string };
  excerpt?: string | null;
};
export type FindingRoadmapItem = { finding_id: string; priority: number; action: string; role: string | null; target_algorithms: string[]; hybrid_mode: string | null; blocking_conditions: string[]; standards_references: string[] };
export type FindingDetailData = {
  investigation_context?: Record<string, Observation>;
  evidence_quality?: Record<string, "observed" | "inferred">;
  application_name?: string | null; application_run_id?: string | null;
  finding: {
    id: string; category: string; confidence: number; identity_label?: string;
    algorithm_family?: string | null; algorithm_variant?: string | null; crypto_role?: string | null;
    algorithm_identification_status?: string; algorithm_identification_confidence?: number;
    confidence_reasons?: string[]; usage_confidence?: number;
    library?: ObservationValue<{ name?: ObservationValue; ecosystem?: ObservationValue }>;
    first_observed_at: string; last_observed_at: string; function?: unknown; protocol?: unknown;
    algorithm?: ObservationValue<{ canonical_name?: unknown; family?: unknown; key_size_bits?: ObservationValue; lifecycle_status?: unknown; parameters?: unknown }>;
    provenance?: { scanner_name?: string; scanner_version?: string; observed_at?: string };
  };
  assessment?: {
    score?: ObservationValue; level?: string; final_priority?: string; mosca_urgency?: string;
    mosca_applicable?: "yes" | "no" | "unknown";
    factors?: { evidence_confidence?: number; rationale?: string[]; cryptographic_obsolescence?: ObservationValue; quantum_exposure?: ObservationValue; exploitability?: ObservationValue; business_impact?: ObservationValue };
  } | null;
  assigned_owner?: string | null; migration_status?: string; in_roadmap?: boolean;
  business_criticality: "critical" | "high" | "medium" | "low" | "unclassified";
  mosca?: Timeline & { urgency: "critical" | "high" | "medium" | "low" | "not_applicable" | "unknown"; timeline_state: "persisted" | "unavailable"; x_source?: string | null } | null;
  evidence_provenance: EvidenceRecord[];
  evidence_authenticity?: { quality: "observed" | "inferred"; summary: string; confidence_applicable: boolean } | null;
  recommendations: Array<{ id: string; priority: number; title: string; action: string; nist_references?: string[]; replacement_algorithm?: ObservationValue<{ canonical_name?: string }> }>;
};
type Props = { fullPage?: boolean; fullPageHref?: string; backHref?: string; open: boolean; loading: boolean; detail: FindingDetailData | null; roadmapItem?: FindingRoadmapItem; onClose: () => void; copiedId: string | null; onCopy: (id: string, label: string) => void; sampleData?: boolean };

function displayValue(value: unknown, evidence: ReadonlySet<string>): string {
  if (typeof value === "string") return safeMetadata(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (!value || typeof value !== "object") return "Unknown";
  const observation = value as Observation;
  if (observation.state === "unknown") return "Unknown";
  if (observation.state === "not_observed") return "Not observed";
  if (observation.state === "confirmed_absent") return observation.basis_evidence_ids?.length && observation.basis_evidence_ids.every(id => evidence.has(id)) ? "Confirmed absent" : "Unknown";
  if ("value" in observation) return displayValue(observation.value, evidence);
  return "Unknown";
}
function Metric({ label, value }: { label: string; value: string }) {
  const technical = ["Algorithm family", "Variant", "Crypto role", "Library", "Key size", "Protocol", "Function / operation", "Scanner", "Scanner version", "Target algorithms", "Hybrid mode"].includes(label);
  const state = value === "Unknown" ? "unknown" : value === "Not observed" ? "not_observed" : value === "Confirmed absent" ? "confirmed_absent" : "observed";
  const meaning = state === "unknown" ? "Available evidence does not establish this value." : state === "not_observed" ? "The scan did not observe a value; this does not prove absence." : state === "confirmed_absent" ? "Supporting evidence establishes absence in the inspected scope." : undefined;
  return <div className="flex min-w-0 flex-col gap-1 rounded-md border border-border bg-muted/30 p-4"><span className="text-xs font-semibold normal-case text-muted-foreground">{label}</span><span className={`inventory-knowledge break-words text-sm font-semibold ${technical ? "font-mono" : "tabular-nums"}`} data-knowledge={state} title={meaning} tabIndex={meaning ? 0 : undefined}><GlossaryText>{value}</GlossaryText></span></div>;
}

export function FindingDetail({ fullPage = false, fullPageHref, backHref = "/#inventory", open, loading, detail, roadmapItem, onClose, copiedId, onCopy, sampleData }: Props) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!open || fullPage) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panel.current?.querySelector<HTMLElement>("button, a[href]")?.focus({ preventScroll: true });
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); onClose(); }
      if (event.key !== "Tab") return;
      const elements = [...(panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), [tabindex="0"]') ?? [])];
      const first = elements[0], last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus({ preventScroll: true }); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus({ preventScroll: true }); }
    };
    document.addEventListener("keydown", keyboard);
    return () => { document.body.style.overflow = previousOverflow; document.removeEventListener("keydown", keyboard); if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true }); };
  }, [open, fullPage, onClose]);
  useEffect(() => {
    if (!open) return;
    const navigate = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (target.closest("input,textarea,select,[contenteditable=true]")) return;
      const sections = [...(panel.current?.querySelectorAll<HTMLElement>("[data-detail-section]") ?? [])];
      if (!sections.length) return;
      const current = sections.findIndex(section => section === target || section.contains(target));
      if (event.key === "j" || event.key === "k") {
        event.preventDefault();
        event.stopPropagation();
        const next = Math.max(0, Math.min(sections.length - 1,
          current + (event.key === "j" ? 1 : -1)));
        sections[next]?.focus();
      } else if (event.key === "Enter" && sections[current] === target) {
        const first = target.querySelector<HTMLElement>("summary,a[href],button:not(:disabled)");
        if (first) { event.preventDefault(); first.focus(); first.click(); }
      }
    };
    document.addEventListener("keydown", navigate, true);
    return () => document.removeEventListener("keydown", navigate, true);
  }, [open]);
  if (!open) return null;
  const finding = detail?.finding;
  const assessment = detail?.assessment;
  const algorithm = finding?.algorithm?.value;
  const knownEvidence = new Set(detail?.evidence_provenance.map(e => e.id) ?? []);
  const value = (v: unknown) => displayValue(v, knownEvidence);
  return <div className={fullPage ? "min-h-screen bg-background" : "fixed inset-0 z-50 flex justify-end"} role={fullPage ? undefined : "dialog"} aria-modal={fullPage ? undefined : true} aria-labelledby="finding-detail-title">
    {!fullPage && <button type="button" tabIndex={-1} aria-label="Close finding detail" onClick={onClose} className="absolute inset-0 bg-foreground/20 backdrop-blur-[2px]" />}
    <aside ref={panel} className={fullPage ? "mx-auto flex w-full max-w-6xl flex-col bg-background" : "finding-slide-over relative flex h-full w-full max-w-3xl flex-col overflow-y-auto border-l border-border bg-background"}>
      <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-border bg-background/95 p-5 backdrop-blur sm:p-6"><div className="min-w-0">{sampleData && <Badge>Sample data</Badge>}<h2 id="finding-detail-title" className={`break-words text-xl font-semibold ${finding ? "font-mono" : ""}`}><GlossaryText>{finding ? safeMetadata(finding.identity_label) === "Unknown" ? value(algorithm?.canonical_name) : safeMetadata(finding.identity_label) : "Finding Investigation"}</GlossaryText></h2><p className="mt-1 text-sm text-muted-foreground">Why this is risky, what was observed, and what to do next.</p><nav aria-label="Breadcrumb" className="mt-2 text-xs"><Link href="/">Workspace</Link> / {detail?.application_name ?? "Unknown application"} / {detail?.application_run_id ?? "Scan"} / Finding</nav></div><div className="flex shrink-0 flex-col items-end gap-2">{fullPageHref && <a href={fullPageHref} target="_blank" rel="noopener noreferrer" className="text-sm font-semibold text-primary">Open full page</a>}{fullPage ? <a href={backHref} className="text-sm font-semibold text-primary">Back to filtered list</a> : <Button variant="ghost" onClick={onClose} aria-label="Close"><X /></Button>}</div></header>
      <div className="flex min-w-0 flex-col gap-6 p-5 sm:p-6">
        {loading && <div role="status" aria-label="Loading Finding evidence and risk factors" className="flex flex-col gap-6" aria-busy="true">
          <span className="sr-only">Loading Finding evidence and risk factors…</span>
          <div aria-hidden="true" className="space-y-6"><div className="h-16 rounded-lg border border-border bg-card" /><div className="grid gap-3 sm:grid-cols-3">{Array.from({ length: 3 }, (_, index) => <div key={index} className="h-24 rounded-lg border border-border bg-card" />)}</div><div className="h-48 rounded-lg border border-border bg-card" /><div className="grid gap-3 sm:grid-cols-2">{Array.from({ length: 4 }, (_, index) => <div key={index} className="h-20 rounded-lg border border-border bg-card" />)}</div></div>
        </div>}
        {!loading && !detail && <Alert><Info /><div><p className="font-semibold">Finding details unavailable</p><p>Close the workspace and retry from the inventory.</p></div></Alert>}
        {!loading && detail && finding && <>
          {detail.application_run_id && <FindingStatus key={`${detail.application_run_id}:${finding.id}`} run={detail.application_run_id} finding={finding.id} />}
          {detail.application_run_id && <FindingTicket key={`ticket:${detail.application_run_id}:${finding.id}`} run={detail.application_run_id} finding={finding.id} />}
          <InvestigationVisuals key={finding.id} detail={detail} />

          <section data-detail-section tabIndex={0} className="flex flex-col gap-3"><h3 className="text-lg font-semibold">Summary</h3><details className="rounded-lg border border-border p-4"><summary className="cursor-pointer text-sm font-semibold">Recorded engine factors and observation states</summary><div className="mt-3 grid gap-3 sm:grid-cols-3"><Metric label="Algorithm weakness" value={value(assessment?.factors?.cryptographic_obsolescence)} /><Metric label="Quantum exposure" value={value(assessment?.factors?.quantum_exposure)} /><Metric label="Exploitability" value={value(assessment?.factors?.exploitability)} /></div></details><div className="flex flex-wrap items-center gap-3"><RiskBadge level={assessment?.final_priority ?? assessment?.level ?? "unassessed"} /><span className="text-sm">{finding.category.replaceAll("_", " ")}</span></div><div className="flex flex-wrap items-center gap-2"><code className="break-all text-xs text-muted-foreground">{finding.id}</code><Button variant="secondary" onClick={() => onCopy(finding.id, "finding-id")}>{copiedId === "finding-id" ? <><Check />Copied</> : <><Copy />Copy ID</>}</Button></div><div className="grid gap-3 sm:grid-cols-3"><Metric label="Assigned owner" value={detail.assigned_owner ?? "Unassigned"} /><Metric label="Added to roadmap" value={detail.in_roadmap ? "Yes" : "No analyst addition"} /></div></section>
          <section data-detail-section tabIndex={0} className="flex flex-col gap-3"><h3 className="text-lg font-semibold">Normalized Cryptographic Identity</h3><div className="grid gap-3 sm:grid-cols-2">
            <Metric label="Identity status" value={value(finding.algorithm_identification_status)} /><Metric label="Algorithm family" value={value(finding.algorithm_family ?? algorithm?.family)} /><Metric label="Variant" value={value(finding.algorithm_variant)} /><Metric label="Crypto role" value={value(finding.crypto_role)} /><Metric label="Library" value={value(finding.library?.value?.name)} /><Metric label="Key size" value={value(algorithm?.key_size_bits)} /><Metric label="Protocol" value={value(finding.protocol)} /><Metric label="Function / operation" value={value(finding.function ?? finding.crypto_role)} /><Metric label="Lifecycle" value={value(algorithm?.lifecycle_status)} /><Metric label="Finding confidence" value={String(finding.confidence)} /><Metric label="Identification confidence" value={value(finding.algorithm_identification_confidence)} /><Metric label="Usage confidence" value={value(finding.usage_confidence)} /><Metric label="Confidence basis" value={finding.confidence_reasons?.map(safeMetadata).join("; ") || "Unknown"} /><Metric label="First observed" value={finding.first_observed_at} /><Metric label="Last observed" value={finding.last_observed_at} /><Metric label="Scanner" value={value(finding.provenance?.scanner_name)} /><Metric label="Scanner version" value={value(finding.provenance?.scanner_version)} />
          </div></section>
          <section data-detail-section tabIndex={0} className="flex flex-col gap-3"><h3 className="text-lg font-semibold">Business Impact</h3><div className="grid gap-3 sm:grid-cols-2"><Metric label="Business criticality" value={detail.business_criticality} /><Metric label="Engine business impact" value={value(assessment?.factors?.business_impact)} /></div><p className="text-sm text-muted-foreground">Missing context limits confidence in prioritization. Lifetime affects the migration timeline; it does not change the persisted final risk score.</p></section>
          <section data-detail-section tabIndex={0} className="flex flex-col gap-3"><h3 className="text-lg font-semibold"><GlossaryText>{"PQC / hybrid recommendation"}</GlossaryText></h3>
            {roadmapItem && <Card><CardContent className="flex flex-col gap-2 pt-6"><p className="font-semibold">Persisted migration roadmap · Priority {roadmapItem.priority}</p><p><GlossaryText>{roadmapItem.action}</GlossaryText></p><Metric label="Cryptographic role" value={roadmapItem.role ?? "Unknown"} /><Metric label="Target algorithms" value={roadmapItem.target_algorithms.join(", ") || "None specified"} /><Metric label="Hybrid mode" value={roadmapItem.hybrid_mode ?? "Not specified"} />{roadmapItem.blocking_conditions.map((c, i) => <p key={i}><GlossaryText>{c}</GlossaryText></p>)}<p className="break-words text-xs">{roadmapItem.standards_references.join(", ")}</p></CardContent></Card>}
            {detail.recommendations.map(r => <Card key={r.id}><CardContent className="flex flex-col gap-2 pt-6"><div className="flex items-start justify-between gap-3"><p className="font-semibold"><GlossaryText>{r.title}</GlossaryText></p><Badge>Priority {r.priority}</Badge></div><p className="text-sm leading-6 text-muted-foreground"><GlossaryText>{r.action}</GlossaryText></p>{r.replacement_algorithm?.state === "observed" && <p className="text-sm">Backend target: {value(r.replacement_algorithm.value?.canonical_name)}</p>}<p className="break-words text-xs text-muted-foreground">{r.nist_references?.join(", ")}</p></CardContent></Card>)}
            {!roadmapItem && !detail.recommendations.length && <p className="text-sm text-muted-foreground">No recommendation returned. Establish the cryptographic role before choosing a migration target.</p>}
            <p className="rounded-lg border border-border p-4 text-sm leading-6 text-muted-foreground"><GlossaryText>{"Selection depends on role, protocol support, performance and interoperability. ML-KEM (FIPS 203) supports key establishment; ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are signature options. A protocol-supported hybrid such as ECDH + ML-KEM may support a staged transition. Evaluate these against the application’s requirements."}</GlossaryText></p>
          </section>
          <section data-detail-section tabIndex={0} className="flex flex-col gap-3"><h3 className="text-lg font-semibold">Affected Applications</h3>{detail.application_name && detail.application_run_id ? <a className="w-fit text-sm font-semibold text-primary underline" href={applicationHref(detail.application_run_id, detail.application_name)}>{detail.application_name} → View affected inventory</a> : <p className="text-sm text-muted-foreground">Unknown — no linked application was returned.</p>}</section>
        </>}
      </div>
    </aside>
  </div>;
}
export default FindingDetail;
