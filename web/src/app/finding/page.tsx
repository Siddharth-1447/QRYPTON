"use client";

import { useEffect, useState } from "react";
import { FindingDetail, type FindingDetailData } from "@/components/finding-detail";
import { API_BASE } from "@/lib/api";
import { readInventoryView, writeInventoryView } from "@/lib/inventory-view";

export default function FindingPage() {
  const [detail, setDetail] = useState<FindingDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [backHref, setBackHref] = useState("/#inventory");
  const [copied, setCopied] = useState<string | null>(null);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("finding_id"), run = params.get("run_id");
    const controller = new AbortController();
    const view = writeInventoryView("", readInventoryView(params.get("view") ?? ""));
    const back = new URLSearchParams(view);
    if (run) back.set("id", run);
    // The destination is constructed locally; URL parameters cannot select an external site.
    window.setTimeout(() => setBackHref(`/?${back}#inventory`), 0);
    if (!id || !run) { window.setTimeout(() => setLoading(false), 0); return; }
    fetch(`${API_BASE}/api/v1/findings/${encodeURIComponent(id)}?run_id=${encodeURIComponent(run)}`, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]), cache: "no-store" })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<FindingDetailData>; })
      .then((data) => { if (!controller.signal.aborted) setDetail(data); })
      .catch(() => { if (!controller.signal.aborted) setDetail(null); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, []);
  return <FindingDetail fullPage open loading={loading} detail={detail} backHref={backHref} onClose={() => {}} copiedId={copied} onCopy={(id) => { void navigator.clipboard.writeText(id).then(() => setCopied(id)).catch(() => {}); }} />;
}
