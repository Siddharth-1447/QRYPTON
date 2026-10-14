"use client";

import { useEffect, useState } from "react";
import { API_BASE } from "@/lib/api";
import { fetchScanStatus, TERMINAL_FAILURE, TERMINAL_SUCCESS } from "@/lib/scan-polling";

const STORAGE_KEY = "qrypton.scan-notifications.v1";
type TrackedScan = { id: string; outcome: string | null };

function readTracked(): TrackedScan[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]");
    return Array.isArray(value) ? value.filter((row): row is TrackedScan => row && typeof row.id === "string" && (row.outcome === null || typeof row.outcome === "string")).slice(-100) : [];
  } catch { return []; }
}

export function trackScan(id: string) {
  try {
    const scans = readTracked().filter((row) => row.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...scans, { id, outcome: null }].slice(-100)));
    window.dispatchEvent(new Event("qrypton-scan-tracked"));
  } catch { /* The active-page poll still delivers completion when storage is unavailable. */ }
}

export function ScanNotifications({ onSettled }: { onSettled: () => void }) {
  const [scans, setScans] = useState<TrackedScan[]>([]);
  useEffect(() => {
    let stopped = false;
    let busy = false;
    const poll = async () => {
      if (busy) return;
      busy = true;
      try {
        const tracked = readTracked();
        const results = await Promise.all(tracked.filter((row) => row.outcome === null).map(async (row) => ({ id: row.id, status: await fetchScanStatus(API_BASE, row.id) })));
        if (stopped) return;
        // Re-read after I/O so dismissals and new submissions cannot be overwritten.
        let changed = false;
        const updated = readTracked().map((row) => {
          const result = results.find((item) => item.id === row.id)?.status;
          if (row.outcome === null && result && !result.pollingError && (TERMINAL_SUCCESS.has(result.status) || TERMINAL_FAILURE.has(result.status))) {
            changed = true;
            return { ...row, outcome: result.status };
          }
          return row;
        });
        if (changed) {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
          onSettled();
        }
        setScans(updated);
      } catch { /* A later poll retries; connection errors are not scan failures. */ }
      finally { busy = false; }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 5000);
    window.addEventListener("qrypton-scan-tracked", poll);
    return () => { stopped = true; window.clearInterval(timer); window.removeEventListener("qrypton-scan-tracked", poll); };
  }, [onSettled]);

  const completed = scans.filter((row) => row.outcome !== null);
  if (!completed.length) return null;
  return <aside aria-label="Scan notifications" aria-live="polite" className="space-y-2">
    {completed.map((row) => <div key={row.id} className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card p-4 text-sm">
      <p className="flex-1">Scan {row.id.slice(-8)}: {row.outcome === "PARTIAL" ? "completed with warnings" : TERMINAL_FAILURE.has(row.outcome!) ? "failed — review Scan History" : "completed"}.</p>
      <a className="font-semibold text-primary" href="#your-scans">Open Scan History</a>
      <button aria-label={`Dismiss notification for ${row.id}`} onClick={() => {
        const updated = readTracked().filter((item) => item.id !== row.id);
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(updated)); } catch { /* In-memory dismissal remains available. */ }
        setScans(updated);
      }}>Dismiss</button>
    </div>)}
  </aside>;
}
