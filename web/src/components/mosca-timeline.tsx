"use client";

import React, { useMemo } from "react";
import { ShieldAlert, ShieldCheck, Clock, AlertTriangle } from "lucide-react";

interface MoscaTimelineProps {
  xDataLifetime?: number; // X: Data confidentiality lifetime in years
  yMigrationYears?: number; // Y: Migration effort in years
  zCrqcHorizon?: number; // Z: CRQC threat horizon in years
}

export function MoscaLinearTimeline({
  xDataLifetime = 7,
  yMigrationYears = 4,
  zCrqcHorizon = 8,
}: MoscaTimelineProps) {
  const currentYear = 2026;
  const x = xDataLifetime;
  const y = yMigrationYears;
  const z = zCrqcHorizon;

  const totalProtectionNeeded = x + y;
  const isExposed = totalProtectionNeeded > z;
  const deficit = Math.max(0, totalProtectionNeeded - z);

  const startYear = currentYear;
  // Span timeline up to max(X+Y, Z) + 3 years to give visual breathing room
  const maxYears = Math.max(totalProtectionNeeded, z) + 3;
  const endYear = startYear + Math.ceil(maxYears);
  const totalSpanYears = endYear - startYear;

  // Yearly tick marks
  const yearTicks = useMemo(() => {
    const ticks: number[] = [];
    for (let yr = startYear; yr <= endYear; yr++) {
      ticks.push(yr);
    }
    return ticks;
  }, [startYear, endYear]);

  // Helper to convert years from startYear into percentage width/position
  const getPct = (yearsFromStart: number) => {
    return Math.min(100, Math.max(0, (yearsFromStart / totalSpanYears) * 100));
  };

  const yBarWidthPct = getPct(y);
  const xBarWidthPct = getPct(x);
  const zLinePct = getPct(z);
  const overhangWidthPct = isExposed ? getPct(totalProtectionNeeded) - zLinePct : 0;

  return (
    <section
      id="mosca-timeline"
      aria-labelledby="mosca-timeline-heading"
      className="qrypton-card overflow-hidden p-6 shadow-md transition-all"
    >
      {/* Header & Status Pill */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="qrypton-kicker">Mosca Security Model (X + Y &gt; Z)</span>
            <span className="text-xs font-mono text-muted-foreground">· Chronological Axis</span>
          </div>
          <h2 id="mosca-timeline-heading" className="mt-1 text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Clock className="h-5 w-5 text-emerald-400" />
            Linear Cryptographic Migration Timeline Scale
          </h2>
        </div>

        {/* Status Badge */}
        {isExposed ? (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-400 text-xs font-semibold tracking-wide shadow-sm">
            <ShieldAlert className="h-4 w-4 text-rose-500 animate-pulse" />
            <span>CRQC EXPOSURE DETECTED: Migration completes after Quantum Horizon</span>
          </div>
        ) : (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-semibold tracking-wide shadow-sm">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <span>WITHIN SECURITY HORIZON: Protection completes prior to Quantum Breach</span>
          </div>
        )}
      </div>

      {/* Metrics Summary Grid */}
      <div className="mt-5 grid grid-cols-1 sm:grid-cols-4 gap-3 font-mono text-xs">
        <div className="p-3 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground uppercase text-[10px]">Data Shelf-Life (X)</span>
          <span className="text-base font-bold text-emerald-400 mt-1">{x} Years</span>
          <span className="text-[10px] text-muted-foreground">Confidentiality requirement</span>
        </div>

        <div className="p-3 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground uppercase text-[10px]">Migration Effort (Y)</span>
          <span className="text-base font-bold text-cyan-400 mt-1">{y} Years</span>
          <span className="text-[10px] text-muted-foreground">PQC transition duration</span>
        </div>

        <div className="p-3 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground uppercase text-[10px]">CRQC Breach Horizon (Z)</span>
          <span className="text-base font-bold text-purple-400 mt-1">{z} Years ({startYear + z})</span>
          <span className="text-[10px] text-muted-foreground">Estimated CRQC arrival</span>
        </div>

        <div className={`p-3 rounded-lg border flex flex-col justify-between ${isExposed ? "bg-rose-950/20 border-rose-500/40 text-rose-300" : "bg-emerald-950/20 border-emerald-500/40 text-emerald-300"}`}>
          <span className="uppercase text-[10px] font-bold">Timeline Balance</span>
          <span className="text-base font-bold mt-1">
            {isExposed ? `+${deficit.toFixed(1)}y Deficit` : `${(z - totalProtectionNeeded).toFixed(1)}y Margin`}
          </span>
          <span className="text-[10px] opacity-80">
            {isExposed ? "Harvest-now-decrypt-later risk" : "Safe protection window"}
          </span>
        </div>
      </div>

      {/* Interactive Linear Graphic Timeline */}
      <div className="mt-8 pt-4 pb-2">
        {/* Top Marker: CRQC Horizon Vertical Pointer */}
        <div className="relative h-6 w-full mb-1">
          <div
            className="absolute top-0 transform -translate-x-1/2 flex flex-col items-center z-20"
            style={{ left: `${zLinePct}%` }}
          >
            <span className="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-400 text-purple-300 font-mono text-[10px] font-bold whitespace-nowrap shadow-sm">
              Z = {startYear + z} CRQC Horizon
            </span>
          </div>
        </div>

        {/* Duration Track Container */}
        <div className="relative h-12 w-full rounded-xl bg-card border border-border/80 p-1 flex items-center shadow-inner overflow-hidden">
          {/* Stacked Bar 1: Migration Time Y (Emerald/Mint Bar) */}
          <div
            className="h-full rounded-l-lg bg-gradient-to-r from-emerald-500 to-teal-400 flex items-center justify-center text-emerald-950 font-mono text-xs font-bold px-2 truncate transition-all duration-500 shadow-sm"
            style={{ width: `${yBarWidthPct}%` }}
            title={`PQC Migration Effort Y = ${y} years`}
          >
            Y: Migration ({y}y)
          </div>

          {/* Stacked Bar 2: Data Confidentiality Lifetime X (Semi-transparent Slate/Amber Bar) */}
          <div
            className="h-full bg-slate-700/60 border-l border-emerald-400/40 flex items-center justify-center text-slate-200 font-mono text-xs font-semibold px-2 truncate transition-all duration-500"
            style={{ width: `${xBarWidthPct}%` }}
            title={`Confidentiality Lifetime X = ${x} years`}
          >
            X: Data Shelf-Life ({x}y)
          </div>

          {/* Overhang Hazard Segment past Z */}
          {isExposed && (
            <div
              className="absolute top-0 bottom-0 bg-rose-500/25 border-y border-r border-rose-500 animate-pulse flex items-center justify-center text-rose-300 font-mono text-[10px] font-bold z-10"
              style={{ left: `${zLinePct}%`, width: `${overhangWidthPct}%` }}
              title={`Quantum Exposure Overhang: +${deficit.toFixed(1)} years`}
            >
              <AlertTriangle className="h-3 w-3 mr-1 text-rose-400" />
              EXPOSURE OVERHANG (+{deficit.toFixed(1)}y)
            </div>
          )}

          {/* Vertical Dashed Line Z (CRQC Arrival Year) */}
          <div
            className="absolute top-0 bottom-0 w-0.5 border-r-2 border-dashed border-purple-400 z-30 pointer-events-none"
            style={{ left: `${zLinePct}%` }}
          />
        </div>

        {/* Year Scale Axis Marks */}
        <div className="relative mt-3 h-8 w-full border-t border-border pt-2 font-mono text-[11px] text-muted-foreground">
          {yearTicks.map((yr) => {
            const yrPct = getPct(yr - startYear);
            const isCrqcYear = yr === startYear + z;
            return (
              <div
                key={yr}
                className="absolute top-0 transform -translate-x-1/2 flex flex-col items-center"
                style={{ left: `${yrPct}%` }}
              >
                <div className={`h-2 w-px ${isCrqcYear ? "bg-purple-400 h-3" : "bg-border"}`} />
                <span className={`mt-1 text-[10px] ${isCrqcYear ? "font-bold text-purple-300" : "text-muted-foreground"}`}>
                  {yr}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend & Explanation */}
      <div className="mt-4 pt-3 border-t border-border/60 flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded bg-emerald-500 inline-block" />
            <span>PQC Migration Effort (Y)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded bg-slate-700 border border-slate-500 inline-block" />
            <span>Confidentiality Lifetime (X)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-0.5 border-r-2 border-dashed border-purple-400 inline-block" />
            <span>CRQC Threat Line (Z)</span>
          </div>
        </div>

        <div className="font-mono text-[11px]">
          Theorem: <strong className="text-foreground">X + Y &le; Z</strong> for Quantum Safety
        </div>
      </div>
    </section>
  );
}

export default MoscaLinearTimeline;
