import { Wordmark } from "./logo";
import { Check, Fingerprint, Search, ShieldCheck, CircleAlert, X } from "lucide-react";
import { TERMINAL_SUCCESS, type ScanStatus } from "@/lib/scan-polling";

export const SCAN_STAGES = ["Acquiring target", "Validating target", "Discovering evidence", "Normalizing observations", "Correlating duplicates", "Assessing risk", "Generating recommendations", "Preparing CBOM"];
const stageNotes = ["Read the target artifacts", "Check scope and access", "Locate cryptographic usage", "Structure the observations", "Link matching evidence", "Evaluate exposure and urgency", "Identify migration paths", "Package findings and provenance"];

export function ScanProgress({ progress }: { progress: ScanStatus | null }) {
  const complete = !!progress && TERMINAL_SUCCESS.has(progress.status);
  const partial = progress?.status === "PARTIAL";
  const completed = progress?.stages?.filter(state => state === "completed").length ?? 0;
  return <section aria-label="Live scan progress" className="scan-execution space-y-4">
    <div className="scan-summary rounded-lg border p-4">
      <div className="flex items-center gap-3"><span className="scan-summary-icon"><Fingerprint className="size-6" aria-hidden="true" /></span><div className="min-w-0 flex-1"><h3 className="text-sm font-semibold">Evidence Pipeline</h3><p className="mt-1 text-sm text-muted-foreground">{progress?.stages ? `${completed} of ${SCAN_STAGES.length} stages confirmed complete` : "Waiting for stage telemetry"}</p></div></div>
      <div role="status" aria-live="polite" aria-atomic="true" className="mt-4 flex items-baseline gap-2">
        <span key={progress?.findings_discovered ?? "waiting"} className="scan-count text-3xl font-semibold tabular-nums">{progress?.findings_discovered ?? "—"}</span><span className="text-sm text-muted-foreground">findings discovered so far</span>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{progress?.findings_discovered == null ? "Waiting for the first confirmed finding count." : "Confirmed unique findings reported by the scan service."}</p>
    </div>
    {!progress?.stages && <p className="text-sm text-muted-foreground">Stage telemetry is not available yet. No stage completion is assumed.</p>}
    <ol className="scan-pipeline" aria-label="Execution stages">
      {SCAN_STAGES.map((label, index) => {
        const state = progress?.stages?.[index] ?? "pending";
        const Icon = state === "completed" ? Check : state === "warning" ? CircleAlert : state === "failed" ? X : state === "running" ? Search : null;
        return <li key={label} data-state={state} aria-current={state === "running" ? "step" : undefined} className="scan-stage">
          <span className="scan-node" aria-hidden="true">{Icon ? <Icon className="size-4" /> : <span>{String(index + 1).padStart(2, "0")}</span>}</span>
          <div key={state} className="scan-stage-content"><div className="min-w-0 flex-1"><p className="text-sm font-medium">{label}</p><p className="mt-1 text-xs text-muted-foreground">{stageNotes[index]}</p></div><span className="scan-stage-status text-xs capitalize">{state}</span></div>
        </li>;
      })}
    </ol>
    {complete && <div role="status" className="scan-result rounded-lg border p-4" data-partial={partial}>
      {partial ? <CircleAlert className="size-5 shrink-0" aria-hidden="true" /> : <ShieldCheck className="size-5 shrink-0" aria-hidden="true" />}
      <div><p className="text-sm font-semibold">{partial ? "Results ready with coverage warnings" : "Inspection complete. Results ready."}</p><p className="mt-1 text-xs">{partial ? "Review coverage and diagnostics before acting on these findings." : "Open the results to review evidence and recommended next steps."}</p></div>
    </div>}
    <p className="text-xs text-muted-foreground"><Wordmark /> analyses artifacts; it does not execute them.</p>
  </section>;
}
