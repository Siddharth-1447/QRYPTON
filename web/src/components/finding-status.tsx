"use client";
import { useEffect, useRef, useState } from "react";
import { workspaceRequest } from "@/lib/api";

export const STAGES = ["New", "Reviewed", "Accepted for Migration", "In Progress", "Mitigated", "Verified", "Closed"];
type State = { status: string; reason: string; version: number; undo_token?: string; undo_expires_at?: number };
export function FindingStatus({ run, finding }: { run: string; finding: string }) {
  const [state, setState] = useState<State | null>(null);
  const [role, setRole] = useState("Viewer");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [undo, setUndo] = useState<State | null>(null);
  const select = useRef<HTMLSelectElement>(null);
  const endpoint = `/scans/${encodeURIComponent(run)}/findings/${encodeURIComponent(finding)}/status`;
  useEffect(() => {
    const controller = new AbortController();
    Promise.all([workspaceRequest<State>(endpoint, { signal: controller.signal }), workspaceRequest<{role: string}>("/session", { signal: controller.signal })])
      .then(([value, actor]) => {
        setState(value); setRole(actor.role);
        if (sessionStorage.getItem("qrypton.focus-status") === "1") {
          sessionStorage.removeItem("qrypton.focus-status");
          if (actor.role === "Security Engineer") requestAnimationFrame(() => select.current?.focus());
        }
      })
      .catch(e => { if (!controller.signal.aborted) setError(String(e.message)); });
    return () => controller.abort();
  }, [endpoint]);
  useEffect(() => {
    if (!undo?.undo_expires_at) return;
    const timer = setTimeout(() => setUndo(null), Math.max(0, undo.undo_expires_at * 1000 - Date.now()));
    return () => clearTimeout(timer);
  }, [undo]);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "e" && !event.ctrlKey && !event.metaKey && !(event.target as HTMLElement).closest("input,textarea,select,[contenteditable=true]")) {
        event.preventDefault(); select.current?.focus();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);
  const change = async (revert = false) => {
    if (!state || busy) return;
    setBusy(true); setError("");
    try {
      const next = await workspaceRequest<State>(revert ? `/finding-status/undo/${undo?.undo_token}` : endpoint, {
        method: revert ? "POST" : "PATCH", ...(revert ? {} : { body: JSON.stringify({ status: target, version: state.version, reason }) }),
      });
      setState(next); setUndo(revert ? null : next); setTarget(""); setReason("");
      window.dispatchEvent(new Event("qrypton:status-changed"));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to save status"); }
    finally { setBusy(false); }
  };
  const next = state ? STAGES[STAGES.indexOf(state.status) + 1] : undefined;
  const editable = role === "Security Engineer" && state && !["Closed", "Risk Accepted"].includes(state.status);
  return <section className="rounded-lg border border-border p-4" aria-label="Finding status lifecycle">
    <h3 className="font-semibold">Finding Status</h3>
    {state && <><span key={state.version} className="status-transition my-3 inline-block rounded-full bg-muted px-3 py-1 text-sm" aria-live="polite">{state.status}</span>{state.reason && <p className="text-sm">Reason: {state.reason}</p>}</>}
    {editable ? <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); void change(); }}>
      <label className="text-sm">Next status<select ref={select} required value={target} onChange={e => setTarget(e.target.value)} className="block rounded border border-border bg-background p-2"><option value="">Choose status</option>{next && <option>{next}</option>}<option>Risk Accepted</option></select></label>
      {target === "Risk Accepted" && <label className="text-sm">Acceptance reason<textarea required maxLength={2000} value={reason} onChange={e => setReason(e.target.value)} className="block rounded border border-border p-2" /></label>}
      <button disabled={busy || !target || (target === "Risk Accepted" && !reason.trim())} className="rounded bg-primary px-3 py-2 text-primary-foreground disabled:opacity-50">Save status</button>
    </form> : <p className="text-xs text-muted-foreground">{role === "Security Engineer" ? "Final lifecycle state." : "Security Engineer access is required to change status."}</p>}
    {error && <p role="alert" className="mt-2 text-sm text-destructive">{error}</p>}
    {undo?.undo_token && <div role="status" className="fixed bottom-5 right-5 z-[100] flex gap-4 rounded-lg border border-border bg-card p-4 shadow-lg">Status changed to {undo.status}<button disabled={busy} className="font-semibold text-primary" onClick={() => void change(true)}>Undo (5 seconds)</button></div>}
  </section>;
}
