"use client";

import { useSyncExternalStore } from "react";

type Duration = "fast" | "base" | "hero";
const preference = "(prefers-reduced-motion: reduce)";
function subscribe(onChange: () => void) {
  const query = window.matchMedia(preference);
  query.addEventListener("change", onChange);
  return () => query.removeEventListener("change", onChange);
}

/** CSS owns the values; the hero specification token is capped for active motion. */
export function readMotionDuration(styles: Pick<CSSStyleDeclaration, "getPropertyValue">, kind: Duration, reduced: boolean): number {
  if (reduced) return 0;
  const value = styles.getPropertyValue(`--duration-${kind}`).trim();
  const milliseconds = parseFloat(value) * (value.endsWith("ms") ? 1 : 1000);
  return Number.isFinite(milliseconds) ? Math.min(250, Math.max(0, milliseconds)) : 0;
}

export function useMotionDuration(kind: Duration = "base"): number {
  return useSyncExternalStore(subscribe, () => readMotionDuration(getComputedStyle(document.documentElement), kind, window.matchMedia(preference).matches), () => 0);
}
