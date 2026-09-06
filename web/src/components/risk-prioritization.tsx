"use client";

import { ArrowUpRight, CheckCircle2, Filter, Info, ShieldAlert } from "lucide-react";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from "@/components/ui/primitives";

type HeatmapCell = { mosca_urgency: string; business_criticality: string; finding_count: number; finding_ids: string[] };
type Finding = { finding_id: string; category: string; algorithm_name: string | null; risk_level: string; risk_score: number | null };
type Props = { heatmap: HeatmapCell[]; inventory: Finding[]; selected: { urgency: string; criticality: string; finding_ids?: string[] } | null; onFilter: (cell: { urgency: string; criticality: string; finding_ids?: string[] } | null) => void; onSelect: (id: string) => void };

const urgency = ["critical", "high", "medium", "low"];
const criticality = ["low", "medium", "high", "critical"];
const tones: Record<string, "critical" | "high" | "medium" | "low"> = { critical: "critical", high: "high", medium: "medium", low: "low" };

export function RiskPrioritization({ heatmap, inventory, selected, onFilter, onSelect }: Props) {
  const queue = [...inventory].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)).slice(0, 6);
  const count = (level: string) => inventory.filter((item) => item.risk_level.toLowerCase() === level).length;

  return (
    <section id="risk" className="flex flex-col gap-4" aria-labelledby="risk-heading">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="qrypton-kicker">Decision layer</p><h2 id="risk-heading" className="mt-1 text-xl font-semibold tracking-tight">Risk &amp; prioritization</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">Focus remediation where business consequence, quantum urgency, and cryptographic weakness overlap.</p></div>
        {selected && <Button variant="secondary" onClick={() => onFilter(null)}><Filter data-icon="inline-start" /> Clear matrix filter</Button>}
      </div>
      <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <Card>
          <CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle>Priority matrix</CardTitle><p className="mt-1 text-sm text-muted-foreground">Select a cell to narrow the findings queue.</p></div><span className="text-xs text-muted-foreground">Urgency × criticality</span></div></CardHeader>
          <CardContent>
            <div className="grid grid-cols-[auto_repeat(4,minmax(0,1fr))] gap-2 text-center text-xs">
              <span className="flex items-end justify-end pb-2 pr-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Urgency / impact</span>
              {criticality.map((level) => <span key={level} className="pb-2 font-semibold capitalize text-muted-foreground">{level}</span>)}
              {urgency.map((u) => <div key={u} className="contents"><span className="flex items-center justify-end pr-2 font-semibold capitalize text-muted-foreground">{u}</span>{criticality.map((c) => { const cell = heatmap.find((item) => item.mosca_urgency?.toLowerCase() === u && item.business_criticality?.toLowerCase() === c); const amount = cell?.finding_count ?? 0; const active = selected?.urgency === u && selected?.criticality === c; return <button key={`${u}-${c}`} type="button" aria-label={`${amount} ${u} urgency, ${c} criticality findings`} onClick={() => onFilter(active ? null : { urgency: u, criticality: c, finding_ids: cell?.finding_ids })} className={`flex min-h-16 flex-col items-center justify-center rounded-md border text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${amount ? `qrypton-risk-${tones[u]}` : "border-border bg-muted/30 text-muted-foreground hover:bg-muted"} ${active ? "ring-2 ring-primary ring-offset-2 ring-offset-background" : ""}`}><span className="font-mono text-lg">{amount}</span><span className="text-[10px] font-normal opacity-75">findings</span></button>; })}</div>)}
            </div>
            <div className="mt-4 flex items-start gap-2 rounded-md border border-border bg-muted/30 p-3 text-xs leading-5 text-muted-foreground"><Info className="mt-0.5 size-4 shrink-0 text-primary" /><span>Cells combine the Mosca planning heuristic with business criticality. A dense upper-right cell means fix those findings first; it does not predict a CRQC date.</span></div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle>Recommended priority queue</CardTitle><p className="mt-1 text-sm text-muted-foreground">Highest-scoring findings first, with context.</p></div><ShieldAlert className="size-5 text-primary" /></div></CardHeader>
          <CardContent><div className="flex flex-col gap-2">{queue.length ? queue.map((item, index) => <button type="button" key={item.finding_id} onClick={() => onSelect(item.finding_id)} className="group flex items-center gap-3 rounded-md border border-border p-3 text-left transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-xs font-semibold text-muted-foreground">{index + 1}</span><span className="min-w-0 flex-1"><span className="flex items-center gap-2"><span className="truncate text-sm font-semibold">{item.algorithm_name ?? "Unidentified algorithm"}</span><Badge tone={tones[item.risk_level] ?? "low"}>{item.risk_level}</Badge></span><span className="mt-1 block truncate text-xs text-muted-foreground">{item.category.replaceAll("_", " ")} · {item.finding_id}</span></span><span className="flex items-center gap-1 font-mono text-sm font-semibold">{item.risk_score ?? "—"}<ArrowUpRight className="size-3 text-muted-foreground transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" /></span></button>) : <div className="flex flex-col items-center gap-2 py-8 text-center"><CheckCircle2 className="size-7 text-emerald-600" /><p className="text-sm font-semibold">No findings require prioritization</p><p className="text-xs text-muted-foreground">A completed scan will populate the decision queue.</p></div>}</div></CardContent>
        </Card>
      </div>
      <div className="grid gap-3 sm:grid-cols-4">{urgency.map((level) => <Card key={level} className="p-4"><div className="flex items-center justify-between"><span className="text-xs font-semibold capitalize text-muted-foreground">{level} risk</span><span className={`size-2 rounded-full qrypton-risk-${tones[level]}`} /></div><p className="mt-2 font-mono text-2xl font-semibold">{count(level)}</p><p className="text-xs text-muted-foreground">findings in scope</p></Card>)}</div>
    </section>
  );
}
