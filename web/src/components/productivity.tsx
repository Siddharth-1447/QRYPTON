"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { GlossaryText } from "./glossary";
import { workspaceRequest } from "@/lib/api";
import { usePathname } from "next/navigation";
import { Search } from "lucide-react";
import { type CryptoInventoryRow, readInventoryView, writeInventoryView } from "@/lib/inventory-view";
import { NAV_SECTIONS } from "./sidebar";
import { formatPrComment, type IntroducedFinding } from "@/lib/pr-comment";
import { ThemeSettings } from "./theme-settings";

type SearchScan = { scan_id: string; target?: string; artifact?: string; timestamp?: string };
type SearchItem = { id: string; label: string; kind: string; href: string };
type CiResult = { provider: string; external_id: string; repository: string; title: string; ref: string; result: "success" | "failure" | "cancelled" | "pending"; url: string; completed_at: string; run_id: string | null; gate_effect: "blocks" | "warns" | "not_evaluated"; introduced: IntroducedFinding[] };
export function ProductivityTools() {
  const [open, setOpen] = useState(false);
  const login = usePathname() === "/login";
  const [query, setQuery] = useState(""); const [index, setIndex] = useState(0);
  const [items, setItems] = useState<SearchItem[]>([]); const [error, setError] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (login) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen(value => !value); }
      if ((e.key === "j" || e.key === "k") && !(e.target as HTMLElement).closest("input,textarea,select,[contenteditable=true]") && !document.querySelector("dialog[open],[aria-modal=true]")) {
        const elements = [...document.querySelectorAll<HTMLElement>("[data-list-item]")].filter(el => el.getClientRects().length);
        if (!elements.length) return;
        e.preventDefault(); const active = elements.findIndex(el => el === document.activeElement || el.contains(document.activeElement));
        elements[Math.max(0, Math.min(elements.length - 1, active + (e.key === "j" ? 1 : -1)))]?.focus();
      }
      if (e.key === "e" && !(e.target as HTMLElement).closest("input,textarea,select,[contenteditable=true]")) {
        const row = (e.target as HTMLElement).closest<HTMLElement>("[data-status-target]")
          ?? [...document.querySelectorAll<HTMLElement>("[data-status-target]")]
            .find(element => element.getClientRects().length > 0);
        if (row && !document.querySelector("[aria-modal=true]")) {
          e.preventDefault();
          sessionStorage.setItem("qrypton.focus-status", "1");
          row.click();
        }
      }
    };
    document.addEventListener("keydown", handler); return () => document.removeEventListener("keydown", handler);
  }, [login]);
  useEffect(() => { if (open) dialog.current?.showModal(); else dialog.current?.close(); }, [open]);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const results = await workspaceRequest<SearchItem[]>(`/workspace-search?q=${encodeURIComponent(query)}`, { signal: controller.signal });
        const params = new URLSearchParams(window.location.search);
        const view = writeInventoryView("", readInventoryView(params.get("view") ?? window.location.search));
        const q = query.toLowerCase();
        const pages = [...NAV_SECTIONS, { id: "scan-comparison", label: "Compare scans" }].filter(p => p.label.toLowerCase().includes(q)).map(p => ({ id: p.id, label: p.label, kind: "Page", href: `/${window.location.pathname === "/" ? window.location.search : ""}#${p.id}` }));
        setItems([...pages, ...results.map(item => item.kind === "Finding" ? {...item, href: `${item.href}&view=${encodeURIComponent(view)}`} : item)].slice(0, 100));
        setIndex(0); setError("");
      } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Search unavailable"); }
    }, 120);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [query, open]);
  useEffect(() => { document.getElementById(`command-${index}`)?.scrollIntoView({ block: "nearest" }); }, [index]);
  return <>
    {/* Extension form processors add attributes to these SSR controls before hydration. */}
    <div className="qrypton-tools">{!login && <button suppressHydrationWarning aria-label="Search" title="Search · Ctrl/⌘ K" className="grid size-10 shrink-0 place-items-center rounded-lg border border-border bg-card" onClick={() => setOpen(true)}><Search className="size-5" aria-hidden="true" /></button>}<ThemeSettings /></div>
    <dialog ref={dialog} onCancel={() => setOpen(false)} onClose={() => setOpen(false)} aria-label="Command palette" className="productivity-dialog">
      <div className="flex gap-3"><input autoFocus role="combobox" aria-label="Search findings, scans, applications and pages" aria-expanded="true" aria-controls="command-results" aria-activedescendant={items[index] ? `command-${index}` : undefined} value={query} onChange={e => setQuery(e.target.value)} placeholder="internet-facing RSA critical" className="w-full rounded border border-border p-3" onKeyDown={e => { if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); setIndex(i => Math.max(0, Math.min(items.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))); } if (e.key === "Enter" && items[index]) window.location.assign(items[index].href); }} /><button onClick={() => setOpen(false)}>Close</button></div>
      <p className="my-2 text-xs text-muted-foreground">Search across workspace findings, applications and scans (first 100 matches). Arrow keys and Enter select.</p>
      {error && <p role="alert">{error}</p>}<ul role="listbox" id="command-results" className="max-h-96 overflow-auto">{items.map((item, i) => <li id={`command-${i}`} key={`${item.kind}-${item.id}`} role="option" aria-selected={i === index}><a href={item.href} className={`block rounded p-3 ${i === index ? "bg-muted" : ""}`} onFocus={() => setIndex(i)}><span className="mr-3 text-xs text-muted-foreground">{item.kind}</span>{item.label}</a></li>)}</ul>{!items.length && <p role="status">No matches</p>}
    </dialog>
  </>;
}

export function RoleHome({ inventory, scans, onSelect }: { inventory: CryptoInventoryRow[]; scans: SearchScan[]; onSelect: (id: string) => void }) {
  const [role, setRole] = useState<string | null>(null); const [detailed, setDetailed] = useState(false);
  const [ciResults, setCiResults] = useState<CiResult[]>([]); const [ciError, setCiError] = useState(""); const [ciLoading, setCiLoading] = useState(true);
  const [copiedComment, setCopiedComment] = useState("");
  useEffect(() => { workspaceRequest<{role: string}>("/session").then(p => setRole(p.role)).catch(() => setRole("Viewer")); queueMicrotask(() => setDetailed(localStorage.getItem("qrypton.detail") === "detailed")); }, []);
  useEffect(() => { workspaceRequest<CiResult[]>("/integrations/ci-results?limit=6").then(setCiResults).catch(e => setCiError(e instanceof Error ? e.message : "CI results unavailable")).finally(() => setCiLoading(false)); }, []);
  const priorities = useMemo(() => [...inventory].sort((a, b) => (a.remediation_rank ?? Infinity) - (b.remediation_rank ?? Infinity)).slice(0, detailed ? 6 : 3), [inventory, detailed]);
  const panels = {
    posture: <section key="posture" className="rounded-lg border border-border p-4"><h3 className="font-semibold">Posture and <GlossaryText>Mosca</GlossaryText> Overview</h3><p className="mt-2 text-2xl tabular-nums">{inventory.filter(f => ["critical", "high"].includes(f.risk_level)).length} critical / high</p><p className="text-sm">{inventory.filter(f => f.timeline_overflow).length} findings exceed the migration timeline</p>{detailed && <p className="text-xs text-muted-foreground">Based on recorded findings and timeline assumptions.</p>}<a href="#dashboard" className="text-sm text-primary">Open posture</a></section>,
    queue: <section key="queue" className="rounded-lg border border-border p-4"><h3 className="font-semibold">Priority Queue</h3>{!priorities.length && <p className="my-2 text-sm text-muted-foreground">No Findings are available for this Scan.</p>}<ul className="my-2 space-y-2">{priorities.map(f => <li key={f.finding_id}><button data-list-item data-status-target className="text-left text-sm text-primary" onClick={() => onSelect(f.finding_id)}><span className="font-mono"><GlossaryText>{f.identity_label}</GlossaryText></span> · {f.risk_level}{detailed && ` · ${f.application ?? "Unknown application"}`}</button></li>)}</ul><a href="#risk" className="text-sm text-primary">Open priority queue</a></section>,
    ci: <section key="ci" className="rounded-lg border border-border p-4"><h3 className="font-semibold">Recent PR / CI Results</h3>{ciLoading && <div role="status" aria-label="Loading PR and CI results" className="my-2 space-y-2"><span className="sr-only">Loading PR and CI results…</span><div aria-hidden="true" className="h-4 w-3/4 rounded bg-muted" /><div aria-hidden="true" className="h-4 w-1/2 rounded bg-muted" /></div>}{!ciLoading && ciError && <p role="alert" className="my-2 text-sm">{ciError}</p>}{!ciLoading && !ciError && !ciResults.length && <p className="my-2 text-sm text-muted-foreground">No PR / CI results published yet.</p>}{!ciLoading && !ciError && !!ciResults.length && <ul className="my-2 space-y-2">{ciResults.slice(0, detailed ? 6 : 3).map(item => <li key={`${item.provider}:${item.repository}:${item.external_id}`}><a className="block text-sm text-primary" href={item.url} target="_blank" rel="noopener noreferrer"><span className="font-medium">{item.title}</span> · {item.result}</a><p className="text-xs">{item.introduced.length} introduced · Gate {item.gate_effect.replaceAll("_", " ")}</p><button type="button" className="text-xs font-semibold text-primary" onClick={() => { void navigator.clipboard.writeText(formatPrComment(item, window.location.origin)).then(() => setCopiedComment(item.external_id)).catch(() => setCiError("Could not copy PR comment; check clipboard permissions")); }}>Copy PR comment</button>{copiedComment === item.external_id && <span role="status" className="ml-2 text-xs">Copied</span>}{detailed && <p className="text-xs text-muted-foreground">{item.repository} · {item.ref} · {new Date(item.completed_at).toLocaleString()}</p>}</li>)}</ul>}<a href="#integrations" className="text-sm text-primary">Manage integrations</a>{detailed && <p className="mt-3 text-xs">{scans.length} recent Scans available in Scan history.</p>}</section>,
  };
  const order: Array<keyof typeof panels> = role === "Security Engineer" ? ["queue", "posture", "ci"] : role === "Developer" ? ["ci", "queue", "posture"] : ["posture", "queue", "ci"];
  if (role === null) return <section aria-label="Loading role home" aria-busy="true" className="space-y-3"><span className="sr-only" role="status">Loading home panels…</span><div aria-hidden="true" className="h-7 w-40 rounded bg-muted" /><div aria-hidden="true" className="grid gap-3 lg:grid-cols-3">{Array.from({ length: 3 }, (_, index) => <div key={index} className="h-40 rounded-lg border border-border bg-card p-4"><div className="h-5 w-2/3 rounded bg-muted" /><div className="mt-6 h-7 w-1/2 rounded bg-muted" /></div>)}</div></section>;
  return <section aria-label={`${role} home`} className="space-y-3"><div className="flex items-center justify-between"><h2 className="text-lg font-semibold">{role} Home</h2><button aria-pressed={detailed} onClick={() => { setDetailed(!detailed); localStorage.setItem("qrypton.detail", !detailed ? "detailed" : "simple"); }} className="rounded border border-border px-3 py-2 text-sm">{detailed ? "Detailed" : "Simple"} · Switch to {detailed ? "Simple" : "Detailed"}</button></div><div className="grid gap-3 lg:grid-cols-3">{order.map(key => panels[key])}</div></section>;
}
