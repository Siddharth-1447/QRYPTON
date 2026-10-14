"use client";

import { useEffect, useState } from "react";
import { Logo } from "./logo";

/** One opening turn; clicks during a turn queue another complete rotation. */
export function HeroLogo({ compact = false, spinOnMount = true }: { compact?: boolean; spinOnMount?: boolean }) {
  const [spin, setSpin] = useState({ active: spinOnMount, queued: 0, turn: 0 });
  useEffect(() => {
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const cancelMotion = () => {
      if (preference.matches) setSpin(current => ({ ...current, active: false, queued: 0 }));
    };
    queueMicrotask(cancelMotion);
    preference.addEventListener("change", cancelMotion);
    return () => preference.removeEventListener("change", cancelMotion);
  }, []);

  return <button
    type="button"
    aria-label="Spin QRYPTON Q symbol"
    className={`qrypton-hero-symbol${compact ? " qrypton-hero-symbol-compact" : ""}`}
    onClick={() => {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      setSpin(current => current.active
        ? { ...current, queued: current.queued + 1 }
        : { active: true, queued: 0, turn: current.turn + 1 });
    }}
  >
    <span className="qrypton-hero-float">
    <span
      key={spin.turn}
      className={`qrypton-hero-symbol-mark${spin.active ? " qrypton-hero-spin" : ""}`}
      onAnimationEnd={event => {
        if (event.target !== event.currentTarget) return;
        setSpin(current => current.queued > 0
          ? { active: true, queued: current.queued - 1, turn: current.turn + 1 }
          : { ...current, active: false });
      }}
    ><Logo tone="on-dark" className="size-full" /></span>
    </span>
  </button>;
}
