"use client";

import { useEffect, useState } from "react";
import { Check, Copy, ExternalLink, Loader2 } from "lucide-react";
import { workspaceRequest } from "@/lib/api";

type TicketDraft = { mode: "github" | "copy"; title: string; body: string };

export function FindingTicket({ run, finding }: { run: string; finding: string }) {
  const [draft, setDraft] = useState<TicketDraft | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "working" | "done" | "error">("loading");
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const path = `/scans/${encodeURIComponent(run)}/findings/${encodeURIComponent(finding)}/ticket`;
  useEffect(() => {
    workspaceRequest<TicketDraft>(path).then(value => { setDraft(value); setState("ready"); }).catch(error => {
      setMessage(error instanceof Error ? error.message : "Ticket draft unavailable"); setState("error");
    });
  }, [path]);

  const create = async () => {
    if (!draft) return;
    setState("working"); setMessage("");
    try {
      if (draft.mode === "github") {
        const result = await workspaceRequest<{ url: string }>(path, { method: "POST" });
        setUrl(result.url); setMessage("GitHub Issue created");
      } else {
        await navigator.clipboard.writeText(`# ${draft.title}\n\n${draft.body}`);
        setMessage("Ticket Markdown copied; paste it into your issue tracker");
      }
      setState("done");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Ticket action failed");
      setState("error");
    }
  };

  return <section aria-label="Finding ticket" className="rounded-lg border border-border p-4">
    <h3 className="font-semibold">Create Ticket</h3>
    <p className="mt-1 text-sm text-muted-foreground">Prefilled from this scan’s evidence, persisted risk and migration plan. Source excerpts and key material stay out of the ticket.</p>
    {draft && <details className="my-3 text-sm"><summary className="cursor-pointer">Review ticket draft</summary><p className="mt-2 font-medium">{draft.title}</p><pre className="mt-2 whitespace-pre-wrap break-words rounded bg-muted p-3 text-xs">{draft.body}</pre></details>}
    <button type="button" onClick={() => void create()} disabled={!draft || state === "working" || (state === "done" && !!url)} className="mt-3 inline-flex items-center gap-2 rounded bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">
      {state === "working" ? <Loader2 className="size-4" /> : state === "done" ? <Check className="size-4" /> : draft?.mode === "copy" ? <Copy className="size-4" /> : null}
      {draft?.mode === "github" ? "Create GitHub Issue" : "Copy ticket Markdown"}
    </button>
    {draft?.mode === "github" && <button type="button" className="ml-2 rounded border border-border px-3 py-2 text-sm" onClick={() => { void navigator.clipboard.writeText(`# ${draft.title}\n\n${draft.body}`).then(() => setMessage("Ticket Markdown copied")).catch(() => setMessage("Clipboard unavailable; select the draft text above")); }}>Copy Markdown</button>}
    {url && <a href={url} target="_blank" rel="noopener noreferrer" className="ml-3 inline-flex items-center gap-1 text-sm text-primary">Open issue <ExternalLink className="size-4" /></a>}
    {state === "loading" && <p role="status" className="mt-2 text-sm">Preparing ticket draft…</p>}
    {message && <p role={state === "error" ? "alert" : "status"} className="mt-2 text-sm">{message}{state === "error" && draft?.mode === "github" ? " You can review and copy the draft above." : ""}</p>}
  </section>;
}
