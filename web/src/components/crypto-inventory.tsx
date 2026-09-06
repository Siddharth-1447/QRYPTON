"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Download, FileText, Filter, Search, SlidersHorizontal } from "lucide-react";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";

type Risk = "critical" | "high" | "medium" | "low" | "informational";
export type CryptoInventoryRow = {
  finding_id: string;
  category: string;
  algorithm_name: string | null;
  algorithm_family: string | null;
  key_size_bits: number | null;
  lifecycle_status: string | null;
  risk_level: Risk;
  risk_score: number | null;
  confidence: number;
  evidence_count: number;
  first_observed_at: string;
  last_observed_at: string;
};

type Props = { items: CryptoInventoryRow[]; query: string; onQueryChange: (value: string) => void; onSelect: (id: string) => void; onClear: () => void };
const filters = ["All risk", "Critical", "High", "Medium", "Low"];

export function CryptoInventory({ items, query, onQueryChange, onSelect, onClear }: Props) {
  const [riskFilter, setRiskFilter] = useState("All risk");
  const [sort, setSort] = useState<{ key: "risk_score" | "algorithm_name" | "last_observed_at"; direction: "asc" | "desc" }>({ key: "risk_score", direction: "desc" });
  const visible = useMemo(() => items.filter((item) => {
    const haystack = [item.finding_id, item.algorithm_name, item.algorithm_family, item.category, item.lifecycle_status].join(" ").toLowerCase();
    return haystack.includes(query.toLowerCase()) && (riskFilter === "All risk" || item.risk_level === riskFilter.toLowerCase());
  }).sort((a, b) => {
    const left = String(a[sort.key] ?? ""); const right = String(b[sort.key] ?? "");
    return left.localeCompare(right, undefined, { numeric: true }) * (sort.direction === "asc" ? 1 : -1);
  }), [items, query, riskFilter, sort]);
  const toggleSort = (key: typeof sort.key) => setSort((current) => ({ key, direction: current.key === key && current.direction === "desc" ? "asc" : "desc" }));
  const exportRows = () => {
    const header = "finding_id,algorithm,family,category,risk_score,risk_level,lifecycle_status,evidence_count";
    const body = visible.map((item) => [item.finding_id, item.algorithm_name ?? "", item.algorithm_family ?? "", item.category, item.risk_score ?? "", item.risk_level, item.lifecycle_status ?? "", item.evidence_count].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","));
    const blob = new Blob([[header, ...body].join("\n")], { type: "text/csv" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "qrypton-crypto-inventory.csv"; link.click(); URL.revokeObjectURL(link.href);
  };
  return <Card id="inventory" className="overflow-hidden">
    <CardHeader className="gap-4 border-b border-border p-5 sm:p-6">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between"><div><p className="qrypton-kicker">Investigation workspace</p><CardTitle className="mt-1 flex items-center gap-2 text-lg"><FileText className="text-primary" aria-hidden="true" />Cryptographic inventory</CardTitle><p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">Every discovered asset, its evidence, and the migration decision it informs.</p></div><div className="flex flex-wrap gap-2"><Button variant="secondary" onClick={exportRows}><Download data-icon="inline-start" />Export CBOM</Button><Button variant="secondary" onClick={exportRows}>Export CSV</Button></div></div>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div className="relative min-w-0 flex-1 lg:max-w-md"><Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true" /><Input value={query} onChange={(event) => onQueryChange(event.target.value)} className="pl-9" placeholder="Search algorithm, asset, or finding ID" aria-label="Search cryptographic inventory" /></div><div className="flex flex-wrap items-center gap-2"><span className="flex items-center gap-1 text-xs font-semibold text-muted-foreground"><Filter data-icon="inline-start" />Risk</span>{filters.map((filter) => <button key={filter} type="button" onClick={() => setRiskFilter(filter)} className={`rounded-md border px-2.5 py-1.5 text-xs font-semibold ${riskFilter === filter ? "border-primary bg-primary text-primary-foreground" : "bg-card text-muted-foreground hover:bg-muted"}`}>{filter}</button>)}<Button variant="ghost" onClick={() => { setRiskFilter("All risk"); onClear(); }}><SlidersHorizontal data-icon="inline-start" />Clear</Button></div></div>
    </CardHeader>
    <CardContent className="p-0"><div className="flex items-center justify-between border-b border-border bg-muted/40 px-5 py-3 text-xs text-muted-foreground"><span><strong className="text-foreground">{visible.length}</strong> of {items.length} discovered assets</span><span>Rows open evidence and finding detail</span></div><div className="overflow-x-auto"><table className="w-full min-w-[1180px] text-left"><thead className="border-b border-border bg-muted/30 text-[11px] uppercase tracking-wide text-muted-foreground"><tr>{[["finding_id","Asset / finding"],["algorithm_name","Algorithm"],["algorithm_family","Type / family"],["last_observed_at","Location / evidence"],["risk_score","Exposure"],["lifecycle_status","Migration status"]].map(([key, label]) => <th key={key} className="px-5 py-3 font-semibold"><button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => toggleSort(key as typeof sort.key)}>{label}{sort.key === key && (sort.direction === "desc" ? <ArrowDown data-icon="inline-end" /> : <ArrowUp data-icon="inline-end" />)}</button></th>)}<th className="px-5 py-3 font-semibold">Business context</th><th className="px-5 py-3 text-right font-semibold">Detail</th></tr></thead><tbody className="divide-y divide-border text-sm">{visible.length ? visible.map((item) => <tr key={item.finding_id} tabIndex={0} onClick={() => onSelect(item.finding_id)} onKeyDown={(event) => event.key === "Enter" && onSelect(item.finding_id)} className="group cursor-pointer hover:bg-muted/40 focus:bg-muted/40 focus:outline-none"><td className="px-5 py-4"><span className="block max-w-[190px] truncate font-mono text-xs font-semibold text-foreground">{item.finding_id}</span><span className="mt-1 block text-xs capitalize text-muted-foreground">{item.category.replaceAll("_", " ")}</span></td><td className="px-5 py-4 font-semibold">{item.algorithm_name ?? "Unknown algorithm"}<span className="mt-1 block text-xs text-muted-foreground">{item.key_size_bits ? `${item.key_size_bits}-bit key` : "Key size not observed"}</span></td><td className="px-5 py-4 text-muted-foreground">{item.algorithm_family ?? "Unclassified"}<span className="mt-1 block text-xs">{item.lifecycle_status ?? "Status pending"}</span></td><td className="px-5 py-4 text-muted-foreground"><span className="block">{item.evidence_count} evidence {item.evidence_count === 1 ? "record" : "records"}</span><span className="mt-1 block text-xs">Observed {new Date(item.last_observed_at).toLocaleDateString()}</span></td><td className="px-5 py-4"><Badge tone={item.risk_level === "informational" ? "info" : item.risk_level}>{item.risk_score == null ? item.risk_level : `${item.risk_score.toFixed(1)} · ${item.risk_level}`}</Badge><span className="mt-1 block text-xs text-muted-foreground">{Math.round(item.confidence * 100)}% confidence</span></td><td className="px-5 py-4"><span className="font-medium">{item.lifecycle_status ?? "Needs assessment"}</span><span className="mt-1 block text-xs text-muted-foreground">Migration planning available</span></td><td className="px-5 py-4 text-muted-foreground">Production asset<br /><span className="text-xs">Business criticality in finding</span></td><td className="px-5 py-4 text-right"><span className="font-semibold text-primary group-hover:underline">Open finding →</span></td></tr>) : <tr><td colSpan={8} className="px-5 py-16 text-center"><p className="font-semibold">No inventory records match these filters.</p><p className="mt-1 text-sm text-muted-foreground">Try a broader search or clear the risk filter.</p><button type="button" onClick={() => { setRiskFilter("All risk"); onClear(); }} className="mt-3 text-sm font-semibold text-primary hover:underline">Clear filters</button></td></tr>}</tbody></table></div></CardContent>
  </Card>;
}

export default CryptoInventory;
