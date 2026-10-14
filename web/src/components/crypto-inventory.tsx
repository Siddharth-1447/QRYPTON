"use client";
import { ExpandDetails } from "@/components/ui/expand-details";

import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, ChevronDown, ChevronRight, Download, FileText, Search } from "lucide-react";
import { RiskBadge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";
import { GlossaryText } from "@/components/glossary";
import { API_BASE, accessHeaders } from "@/lib/api";
import { buildInventoryRows, filterInventory, inventoryCsv, INVENTORY_ROW_HEIGHT, MIGRATION_STATUSES, PRESET_VIEWS, SORT_KEYS, VIEW_DEFAULTS, virtualWindow, type CryptoInventoryRow, type InventoryObservation, type InventoryViewState } from "@/lib/inventory-view";

export type { CryptoInventoryRow } from "@/lib/inventory-view";
type SavedView = { id: string; name: string; state: InventoryViewState };
type Props = { items: CryptoInventoryRow[]; state: InventoryViewState; onViewChange: (patch: Partial<InventoryViewState>, replace?: boolean) => void; onSelect: (id: string) => void; runId: string | null; onActionsComplete: () => Promise<void>; sampleData?: boolean };
const meanings = {
  unknown: "Unknown: available evidence does not establish this value. This is not a low-risk conclusion.",
  not_observed: "Not observed: this scan did not observe a value. Lack of an observation does not prove absence.",
  confirmed_absent: "Confirmed absent: explicit supporting evidence establishes absence within the inspected scope.",
  observed: "Observed: backed by recorded evidence or declared business context.",
};
export function KnowledgeValue({ observation, suffix = "", format }: { observation?: InventoryObservation; suffix?: string; format?: (value: string | number | boolean) => string }) {
  const requested = observation?.state ?? "unknown";
  const state = requested === "confirmed_absent" && !observation?.evidence_ids?.length ? "unknown" : requested;
  const value = observation?.value;
  const label = state === "observed" && value != null ? (format ? format(value) : String(value)) + suffix : state === "not_observed" ? "Not observed" : state === "confirmed_absent" ? "Confirmed absent" : "Unknown";
  const tooltip = [meanings[state], observation?.rationale, observation?.evidence_ids?.length ? `Basis: ${observation.evidence_ids.join(", ")}` : ""].filter(Boolean).join(" ");
  return <span className="inventory-knowledge" data-knowledge={state} title={tooltip} tabIndex={state === "observed" ? undefined : 0} aria-label={`${label}. ${tooltip}`}>{label}</span>;
}
function SelectionBox({ ids, selected, onToggle, label }: { ids: string[]; selected: Set<string>; onToggle: (ids: string[]) => void; label: string }) {
  const ref = useRef<HTMLInputElement>(null);
  const count = ids.filter((id) => selected.has(id)).length;
  const mixed = count > 0 && count < ids.length;
  useEffect(() => { if (ref.current) ref.current.indeterminate = mixed; }, [mixed]);
  return <input ref={ref} type="checkbox" checked={ids.length > 0 && count === ids.length} aria-checked={mixed ? "mixed" : undefined} aria-label={label} onClick={(e) => e.stopPropagation()} onChange={() => onToggle(ids)} className="size-4 accent-primary" />;
}
function FilterSelect({ label, value, values, onChange, allowAll = true }: { label: string; value: string; values: Array<string | [string, string]>; onChange: (value: string) => void; allowAll?: boolean }) {
  const options = values.map((item) => typeof item === "string" ? [item, item.replaceAll("_", " ")] : item);
  if (value && !options.some(([key]) => key === value)) options.push([value, value.replaceAll("_", " ")]);
  return <label className="flex min-w-32 flex-col gap-1 text-xs font-semibold text-muted-foreground">{label}<select value={value} onChange={(e) => onChange(e.target.value)} className="h-9 rounded-md border border-input bg-card px-2 text-sm text-foreground">{allowAll && <option value="">All</option>}{options.map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></label>;
}
const columns: Array<{ label: string; sort?: string; width: number }> = [
  { label: "Selection", width: 52 }, { label: "Finding ID / category", sort: "finding_id", width: 190 },
  { label: "Algorithm / identity", sort: "algorithm_name", width: 220 }, { label: "Family / status", width: 170 },
  { label: "Function", width: 150 }, { label: "Key size / mode", width: 190 },
  { label: "Artifact type", width: 150 }, { label: "Location / evidence / last observed", sort: "last_observed_at", width: 280 },
  { label: "Application", sort: "application", width: 190 }, { label: "Exposure", width: 150 },
  { label: "Business criticality", sort: "business_criticality", width: 150 }, { label: "Data lifetime", width: 160 },
  { label: "Quantum status", width: 160 }, { label: "Risk score / tier", sort: "risk_level", width: 180 },
  { label: "Confidence", sort: "confidence", width: 170 }, { label: "Migration status / owner", sort: "migration_status", width: 210 },
  { label: "Algorithm lifecycle", width: 170 }, { label: "Detail", width: 150 },
];

export function CryptoInventory({ items, state, onViewChange, onSelect, runId, onActionsComplete, sampleData }: Props) {
  const query = useDeferredValue(state.q);
  const visible = useMemo(() => filterInventory(items, { ...state, q: query }), [items, state, query]);
  const displayRows = useMemo(() => buildInventoryRows(visible, state), [visible, state]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [scrollTop, setScrollTop] = useState(0);
  const scroller = useRef<HTMLDivElement>(null);
  const windowRows = virtualWindow(displayRows.length, Math.max(0, scrollTop - 48), 560);
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [viewName, setViewName] = useState("");
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selectedIds = useMemo(() => items.filter((r) => selected.has(r.finding_id)).map((r) => r.finding_id), [items, selected]);
  const expanded = new Set(state.expanded);
  const resetKey = JSON.stringify({ ...state, expanded: [] });
  useEffect(() => { scroller.current?.scrollTo({ top: 0, left: 0 }); }, [resetKey]);
  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/api/v1/inventory/views`, { signal: AbortSignal.timeout(5000), cache: "no-store" })
      .then(async (r) => { if (!r.ok) throw new Error(); return r.json() as Promise<SavedView[]>; })
      .then((views) => { if (!cancelled && Array.isArray(views)) setSavedViews(views); })
      .catch(() => { if (!cancelled) setError("Saved views could not be loaded. URL sharing and presets remain available."); });
    return () => { cancelled = true; };
  }, []);
  const toggleSelection = (ids: string[]) => setSelected((current) => {
    const next = new Set(current), remove = ids.every((id) => next.has(id));
    for (const id of ids) { if (remove) next.delete(id); else next.add(id); }
    return next;
  });
  const toggleExpanded = (key: string) => onViewChange({ expanded: expanded.has(key) ? state.expanded.filter((v) => v !== key) : [...state.expanded, key] });
  const toggleSort = (key: string) => onViewChange({ sort: key, direction: state.sort === key && state.direction === "desc" ? "asc" : "desc" });
  const bulkAction = async (action: "roadmap" | "owner") => {
    if (!runId || !selectedIds.length || busy) return;
    setBusy(true); setError(null); setMessage(null);
    try {
      const response = await fetch(`${API_BASE}/api/v1/inventory/actions`, { method: "PATCH", headers: { "Content-Type": "application/json", ...accessHeaders() }, body: JSON.stringify({ run_id: runId, finding_ids: selectedIds, action, ...(action === "owner" ? { owner: owner.trim() } : {}) }), signal: AbortSignal.timeout(15000) });
      if (!response.ok) { const data = await response.json().catch(() => null); throw new Error(typeof data?.detail === "string" ? data.detail : `Bulk action failed (HTTP ${response.status}).`); }
      const result = await response.json();
      setMessage(`Saved ${action === "roadmap" ? "roadmap additions" : action === "owner" ? "owner assignments" : "migration status"} for ${result.updated} findings.`);
      try { await onActionsComplete(); } catch { setError("Changes were saved, but the refreshed view is unavailable. Reload to retrieve them."); }
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Bulk action could not be saved."); }
    finally { setBusy(false); }
  };
  const saveView = async () => {
    if (!viewName.trim() || saving) return;
    setSaving(true); setError(null);
    try {
      const response = await fetch(`${API_BASE}/api/v1/inventory/views`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: viewName.trim(), state }), signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error(`View could not be saved (HTTP ${response.status}).`);
      const saved = await response.json() as SavedView;
      setSavedViews((current) => [...current.filter((v) => v.id !== saved.id), saved]);
      setViewName(""); setMessage(`Saved view: ${saved.name}`);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "View could not be saved."); }
    finally { setSaving(false); }
  };
  const exportRows = () => {
    const url = URL.createObjectURL(new Blob([inventoryCsv(visible, sampleData)], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = "qrypton-crypto-inventory.csv"; link.click(); URL.revokeObjectURL(url);
  };
  const filter = (key: keyof InventoryViewState, label: string, values: Array<string | [string, string]>) => <FilterSelect key={key} label={label} allowAll={key !== "sort"} value={String(state[key])} values={values} onChange={(value) => onViewChange({ [key]: value })} />;
  const filteredIds = new Set(visible.map((r) => r.finding_id));
  return <Card id="inventory" className="overflow-hidden">
    <CardHeader className="gap-4 border-b border-border p-6">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><CardTitle className="flex items-center gap-2 text-lg"><FileText className="text-secondary" />Cryptographic Inventory</CardTitle><p className="mt-1 text-sm text-muted-foreground">Start with application context. Expand an algorithm to inspect findings and their evidence.</p></div><Button variant="secondary" onClick={exportRows}><Download />Export CSV</Button></div>
      <ExpandDetails title="Inventory Filters"><div className="flex flex-wrap items-center gap-3"><div className="relative min-w-64 flex-1"><Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" /><Input className="pl-9" value={state.q} onChange={(e) => onViewChange({ q: e.target.value }, true)} placeholder="Search application, algorithm, owner, location, or evidence" aria-label="Search cryptographic inventory" /></div><div className="flex gap-2" role="group" aria-label="Inventory layout"><Button variant={state.view === "grouped" ? "primary" : "secondary"} aria-pressed={state.view === "grouped"} onClick={() => onViewChange({ view: "grouped" })}>Grouped</Button><Button variant={state.view === "raw" ? "primary" : "secondary"} aria-pressed={state.view === "raw"} onClick={() => onViewChange({ view: "raw" })}>Raw table</Button></div><Button variant="ghost" onClick={() => onViewChange({ ...VIEW_DEFAULTS, expanded: [] })}>Clear filters</Button><Button variant="secondary" onClick={async () => { try { const link = new URL(window.location.href); if (runId) link.searchParams.set("id", runId); link.hash = "inventory"; await navigator.clipboard.writeText(link.href); setMessage("View link copied."); } catch { setError("Copy the address bar URL to share this view."); } }}>Copy view link</Button></div>
      <div className="flex flex-wrap gap-3" aria-label="Inventory filters">
        {filter("application", "Application", [...new Set(items.map(r => r.application ?? "Unknown"))].sort())}
        {filter("algorithm", "Algorithm", [...new Set(items.map(r => r.algorithm_name ?? "Unknown"))].sort())}
        {filter("risk", "Risk", [["critical,high", "Critical + High"], "critical", "high", "medium", "low", "informational", "unknown", "unassessed"])}
        {filter("family", "Algorithm family", [...new Set(items.map((r) => r.algorithm_family ?? "unknown"))].sort())}
        {filter("quantum", "Quantum vulnerability", [["vulnerable", "Vulnerable"], ["resistant", "Resistant"], ["quantum_relevant", "Quantum relevant"], ["unknown", "Unknown"]])}
        {filter("surface", "Source surface", ["source", "binary", "library", "container", "kms", "api", "unknown"])}
        {filter("criticality", "Business criticality", ["critical", "high", "medium", "low", "unclassified"])}
        {filter("environment", "Environment", [...new Set(["production", "staging", "development", "unknown", ...items.map((r) => r.environment ?? "unknown")])].sort())}
        {filter("exposure", "Exposure", [["yes", "Internet-facing"], ["no", "Not internet-facing"], ["unknown", "Unknown"]])}
        {filter("confidence", "Confidence", [["high", "High (≥80%)"], ["medium", "Medium (50–79%)"], ["low", "Low (<50%)"]])}
        {filter("migration", "Migration status", [["actionable", "Not migrated or accepted"], ...MIGRATION_STATUSES])}
        {filter("context", "Business context", [["missing", "Missing context"]])}
        {filter("timeline", "Mosca timeline", [["overflow", "X+Y>Z (applicable only)"]])}
        {filter("urgency", "Mosca urgency", ["critical", "high", "medium", "low", "not_applicable", "unknown"])}
        {filter("sort", "Sort by", SORT_KEYS.map((key) => [key, key.replaceAll("_", " ")]))}
        <Button variant="ghost" className="self-end" onClick={() => onViewChange({ direction: state.direction === "desc" ? "asc" : "desc" })}>{state.direction === "desc" ? <ArrowDown /> : <ArrowUp />}{state.direction === "desc" ? "Descending" : "Ascending"}</Button>
      </div>
      <div className="flex flex-wrap items-center gap-2" aria-label="Saved inventory views"><span className="text-xs font-semibold text-muted-foreground">Saved views</span>{Object.entries(PRESET_VIEWS).map(([name, preset]) => <Button variant="secondary" key={name} onClick={() => onViewChange({ ...VIEW_DEFAULTS, ...preset, expanded: [] })}>{name}</Button>)}{savedViews.map((view) => <div key={view.id} className="flex items-center gap-1"><Button variant="secondary" onClick={() => onViewChange({ ...VIEW_DEFAULTS, ...view.state })}>{view.name}</Button><button className="px-2 text-muted-foreground" aria-label={`Delete saved view ${view.name}`} onClick={async () => { try { const r = await fetch(`${API_BASE}/api/v1/inventory/views/${encodeURIComponent(view.id)}`, { method: "DELETE", signal: AbortSignal.timeout(5000) }); if (!r.ok) throw new Error(); setSavedViews((current) => current.filter((v) => v.id !== view.id)); } catch { setError("Saved view could not be deleted."); } }}>×</button></div>)}<Input value={viewName} maxLength={80} onChange={(e) => setViewName(e.target.value)} placeholder="Name this view" aria-label="Saved view name" className="max-w-48" /><Button variant="secondary" disabled={saving || !viewName.trim()} onClick={() => void saveView()}>{saving ? "Saving…" : "Save view"}</Button></div>
      </ExpandDetails>
      {message && <p role="status" className="text-sm">{message}</p>}{error && <p role="alert" className="text-sm">{error}</p>}
    </CardHeader>
    <CardContent className="p-0">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-3 text-xs text-muted-foreground"><span><strong className="text-foreground">{visible.length}</strong> of {items.length} findings · {selectedIds.length} selected{selectedIds.some((id) => !filteredIds.has(id)) ? " (including hidden findings)" : ""}</span><span>Unknown ≠ not observed ≠ confirmed absent. Hover or focus a value for its meaning.</span></div>
      {selectedIds.length > 0 && <div className="flex flex-wrap items-center gap-3 border-b border-border bg-muted/30 px-6 py-3" aria-label="Bulk investigation actions"><Button variant="secondary" disabled={busy || !runId} onClick={() => void bulkAction("roadmap")}>Add to migration roadmap</Button><Input value={owner} maxLength={256} onChange={(e) => setOwner(e.target.value)} aria-label="Assign owner" placeholder="Owner or team" className="max-w-48" /><Button variant="secondary" disabled={busy || !owner.trim() || !runId} onClick={() => void bulkAction("owner")}>Assign owner</Button><span className="text-xs">Open a finding to change its status.</span><Button variant="ghost" disabled={busy} onClick={() => setSelected(new Set())}>Clear selection</Button>{busy && <span role="status" className="text-xs">Saving decisions…</span>}</div>}
      <div ref={scroller} className="inventory-scroll overflow-auto" style={{ height: 560 }} onKeyDown={event => {
        if (!["j", "k"].includes(event.key) || (event.target as HTMLElement).closest("input,textarea,select")) return;
        event.preventDefault(); event.stopPropagation();
        const current = Number((event.target as HTMLElement).closest("[aria-rowindex]")?.getAttribute("aria-rowindex") ?? 1) - 2;
        const next = Math.max(0, Math.min(displayRows.length - 1, current + (event.key === "j" ? 1 : -1)));
        scroller.current?.scrollTo({top: next * INVENTORY_ROW_HEIGHT});
        setScrollTop(next * INVENTORY_ROW_HEIGHT);
        requestAnimationFrame(() => scroller.current?.querySelector<HTMLElement>(`[aria-rowindex="${next + 2}"]`)?.focus({preventScroll: true}));
      }} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} tabIndex={0} aria-label="Scrollable cryptographic inventory">
        <table className="inventory-table w-full table-fixed text-left" style={{ minWidth: columns.reduce((n, c) => n + c.width, 0) }} aria-rowcount={displayRows.length + 1}>
          <colgroup>{columns.map((c) => <col key={c.label} style={{ width: c.width }} />)}</colgroup>
          <thead className="sticky top-0 z-10 border-b border-border bg-card text-xs text-muted-foreground"><tr style={{ height: 48 }}>{columns.map((c, i) => <th key={c.label} className="px-3 py-2 font-semibold" scope="col" aria-sort={c.sort === state.sort ? state.direction === "asc" ? "ascending" : "descending" : undefined}>{i === 0 ? <SelectionBox ids={visible.map((r) => r.finding_id)} selected={selected} onToggle={toggleSelection} label="Select all filtered findings" /> : c.sort ? <button className="flex items-center gap-1" onClick={() => toggleSort(c.sort!)}>{c.label}{c.sort === state.sort && (state.direction === "desc" ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}</button> : c.label}</th>)}</tr></thead>
          <tbody className="text-sm">
            {windowRows.before > 0 && <tr aria-hidden="true"><td colSpan={columns.length} style={{ height: windowRows.before, padding: 0 }} /></tr>}
            {displayRows.slice(windowRows.start, windowRows.end).map((row, index) => {
              const rowIndex = windowRows.start + index + 2;
              if (row.kind === "application" || row.kind === "algorithm") return <tr data-list-item tabIndex={0} onKeyDown={e => { if (e.target === e.currentTarget && e.key === "Enter") toggleExpanded(row.key); }} key={row.key} aria-rowindex={rowIndex} className="border-b border-border bg-muted/30" style={{ height: INVENTORY_ROW_HEIGHT }}><td className="px-3"><SelectionBox ids={row.items.map((r) => r.finding_id)} selected={selected} onToggle={toggleSelection} label={`Select ${row.items.length} findings in ${row.label}`} /></td><td colSpan={columns.length - 1} className="px-3"><div className={`inventory-group-summary flex items-center gap-3 ${row.kind === "algorithm" ? "pl-6" : ""}`}><button className="flex max-w-2xl items-center gap-2 text-left font-semibold" aria-expanded={expanded.has(row.key)} onClick={() => toggleExpanded(row.key)}>{expanded.has(row.key) ? <ChevronDown className="size-4 shrink-0" /> : <ChevronRight className="size-4 shrink-0" />}<span className={row.kind === "algorithm" ? "font-mono font-semibold" : undefined}><GlossaryText>{row.label}</GlossaryText></span></button><span className="text-xs text-muted-foreground">{row.items.length} findings · {row.evidenceCount} evidence records · Highest known risk</span><RiskBadge level={row.highest} />{row.uncertain > 0 && <span className="inventory-knowledge text-xs" data-knowledge="unknown" title="These findings have unknown risk or lack an assessment.">{row.uncertain} unknown / unassessed</span>}</div></td></tr>;
              if (!("item" in row)) return null;
              const item = row.item, evidence = row.kind === "evidence" ? row.evidence : null;
              const key = `f:${item.finding_id}`, observations = item.observations ?? {};
              const risk = item.risk_assessment_state === "unassessed" ? "unassessed" : item.risk_level;
              const location = evidence?.location ?? item.evidence_rows?.find((e) => e.location)?.location;
              return <tr data-list-item data-status-target key={row.key} aria-rowindex={rowIndex} aria-selected={selected.has(item.finding_id)} data-risk={risk} className={`inventory-data-row border-b border-border cursor-pointer ${selected.has(item.finding_id) ? "bg-selected" : "hover:bg-muted/30"}`} style={{ height: INVENTORY_ROW_HEIGHT }} onClick={() => onSelect(item.finding_id)} onKeyDown={(e) => { if (e.target === e.currentTarget && e.key === "Enter") onSelect(item.finding_id); }} tabIndex={0}>
                <td className="px-3"><SelectionBox ids={[item.finding_id]} selected={selected} onToggle={toggleSelection} label={`Select finding ${item.finding_id}`} /></td>
                <td className="px-3"><div className="flex items-center gap-1">{!evidence && <button aria-label={`Expand evidence for ${item.finding_id}`} aria-expanded={expanded.has(key)} onClick={(e) => { e.stopPropagation(); toggleExpanded(key); }}>{expanded.has(key) ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</button>}<span className="truncate font-mono text-xs font-semibold" title={evidence?.id ?? item.finding_id}>{evidence?.id ?? item.finding_id}</span></div><span className="block truncate text-xs text-muted-foreground">{evidence ? evidence.kind : item.category.replaceAll("_", " ")}</span>{sampleData && <span className="text-xs text-muted-foreground">Sample data</span>}</td>
                <td className="px-3"><div className="truncate font-mono font-semibold" title={item.algorithm_name ?? item.identity_label}>{item.algorithm_name ? <GlossaryText>{item.algorithm_name}</GlossaryText> : <KnowledgeValue observation={observations.algorithm} />}</div><span className="block truncate font-mono text-xs text-muted-foreground" title={item.identity_label}>{item.identity_label}</span><span className="block truncate text-xs text-muted-foreground">{item.algorithm_variant ?? "Variant not observed"} · {item.library_name ?? <KnowledgeValue observation={observations.library} />}</span></td>
                <td className="px-3"><span className="block truncate font-mono">{item.algorithm_family ?? <KnowledgeValue />}</span><span className="block truncate text-xs text-muted-foreground">Identity: {item.identity_status}</span></td>
                <td className="px-3 font-mono"><KnowledgeValue observation={observations.function} /></td>
                <td className="px-3 font-mono"><KnowledgeValue observation={observations.key_size} suffix=" bits" /><span className="mt-1 block"><KnowledgeValue observation={observations.mode} /></span></td>
                <td className="px-3"><span className="block truncate">{item.artifact_type ?? <KnowledgeValue />}</span><span className="text-xs text-muted-foreground">{evidence?.surface ?? item.source_surfaces?.join(", ") ?? "Unknown surface"}</span></td>
                <td className="px-3"><span className="block truncate font-mono text-xs" title={location ?? "This scan did not observe a location."}>{location ?? <KnowledgeValue observation={{ state: "not_observed", value: null }} />}</span><span className="block text-xs text-muted-foreground">{evidence ? "Evidence record" : `${item.evidence_count} evidence records`} · {item.last_observed_at?.slice(0, 10) || "Not observed"}</span>{evidence?.excerpt && <span className="block truncate font-mono text-xs text-muted-foreground" title={evidence.excerpt}>{evidence.excerpt}</span>}</td>
                <td className="px-3"><span className="block truncate" title={item.application ?? "Application has not been established."}>{item.application ?? <KnowledgeValue />}</span><span className="block truncate text-xs text-muted-foreground">{item.environment ?? "Unknown environment"}</span></td>
                <td className="px-3"><KnowledgeValue observation={observations.exposure} format={(v) => v === true ? "Internet-facing" : v === false ? "Not internet-facing" : "Unknown"} /></td>
                <td className="px-3"><KnowledgeValue observation={observations.criticality} /></td>
                <td className="px-3"><KnowledgeValue observation={observations.data_lifetime} suffix=" years" /></td>
                <td className="px-3"><span className="inventory-knowledge" data-knowledge={!item.quantum_status || item.quantum_status === "unknown" ? "unknown" : "observed"} title={item.quantum_rationale ?? meanings.unknown}>{(item.quantum_status ?? "unknown").replaceAll("_", " ")}</span></td>
                <td className="px-3"><RiskBadge level={risk} /><span className="mt-1 block text-xs text-muted-foreground">{item.risk_score == null ? "Score unavailable" : `${item.risk_score.toFixed(1)} / 100`}</span></td>
                <td className="px-3"><span title={item.confidence_reasons.join("; ")}>{Math.round((evidence?.confidence ?? item.confidence) * 100)}% evidence</span><span className="block text-xs text-muted-foreground">{Math.round(item.identification_confidence * 100)}% identity · {Math.round(item.usage_confidence * 100)}% usage</span></td>
                <td className="px-3"><span className="block truncate">{(item.migration_status ?? "untriaged").replaceAll("_", " ")}{item.in_roadmap ? " · Roadmap" : ""}</span><span className="block truncate text-xs text-muted-foreground" title={item.assigned_owner ?? "Owner has not been assigned."}>{item.assigned_owner ?? "Unassigned owner"}</span></td>
                <td className="px-3">{item.lifecycle_status ?? <KnowledgeValue />}</td><td className="px-3"><button className="text-xs font-semibold text-primary" onClick={(e) => { e.stopPropagation(); onSelect(item.finding_id); }}>Open finding →</button></td>
              </tr>;
            })}
            {windowRows.after > 0 && <tr aria-hidden="true"><td colSpan={columns.length} style={{ height: windowRows.after, padding: 0 }} /></tr>}
            {!displayRows.length && <tr><td colSpan={columns.length} className="p-12 text-center">No inventory records match this view. <button className="font-semibold text-primary" onClick={() => onViewChange({ ...VIEW_DEFAULTS, expanded: [] })}>Clear filters</button></td></tr>}
          </tbody>
        </table>
      </div>
      <p className="border-t border-border px-6 py-3 text-xs text-muted-foreground">{displayRows.length} group, finding, and evidence rows · Export includes all {visible.length} filtered findings.</p>
    </CardContent>
  </Card>;
}

export default CryptoInventory;
