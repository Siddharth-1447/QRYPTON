"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import { readInventoryView, writeInventoryView, type InventoryViewState } from "./inventory-view";

const CHANGE_EVENT = "qrypton-inventory-view";
const subscribe = (callback: () => void) => {
  window.addEventListener("popstate", callback);
  window.addEventListener(CHANGE_EVENT, callback);
  return () => { window.removeEventListener("popstate", callback); window.removeEventListener(CHANGE_EVENT, callback); };
};
const snapshot = () => window.location.search;
const serverSnapshot = () => "";

export function useInventoryView(runId?: string | null) {
  const search = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  const state = useMemo(() => readInventoryView(search), [search]);
  const update = useCallback((patch: Partial<InventoryViewState>, replace = false) => {
    const url = new URL(window.location.href);
    const current = readInventoryView(url.search);
    if (runId) url.searchParams.set("id", runId);
    url.search = writeInventoryView(url.search, { ...current, ...patch });
    window.history[replace ? "replaceState" : "pushState"]({}, "", `${url.pathname}${url.search}${url.hash}`);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, [runId]);
  return [state, update] as const;
}
