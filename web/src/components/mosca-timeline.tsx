"use client";

import { GlossaryText } from "@/components/glossary";
import React from "react";
import { RiskBadge } from "@/components/ui/primitives";
import { Clock, AlertTriangle } from "lucide-react";

interface MoscaTimelineProps {
  xDataLifetime?: number; // X: Data confidentiality lifetime in years
  yMigrationYears?: number; // Y: Migration effort in years
  zCrqcHorizon?: number; // Z: CRQC threat horizon in years
}

export function MoscaLinearTimeline({
  xDataLifetime,
  yMigrationYears,
  zCrqcHorizon,
}: MoscaTimelineProps) {
  if (xDataLifetime == null || yMigrationYears == null || zCrqcHorizon == null ||
      ![xDataLifetime, yMigrationYears, zCrqcHorizon].every((value) => Number.isFinite(value) && value >= 0)) {
    return <section id="mosca-timeline" className="qrypton-card p-6"><h2 className="text-xl font-semibold"><GlossaryText>{"Mosca timeline"}</GlossaryText></h2><RiskBadge level="unknown" /><p className="mt-2 text-muted-foreground">Timeline inputs unavailable. Review the persisted business context for this finding.</p></section>;
  }
  const currentYear = new Date().getFullYear();
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
  const yearTicks = (() => {
    const ticks: number[] = [];
    for (let yr = startYear; yr <= endYear; yr += Math.max(1, Math.ceil(totalSpanYears / 8))) {
      ticks.push(yr);
    }
    return ticks;
  })();

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
      className="qrypton-card overflow-hidden p-6 shadow-md qrypton-motion"
    >
      {/* Header & Status Pill */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-6">
        <div>
          <h2 id="mosca-timeline-heading" className="mt-1 text-xl font-semibold tracking-normal text-foreground flex items-center gap-2">
            <Clock className="h-5 w-5 text-secondary" />
            Linear Cryptographic Migration Timeline Scale
          </h2>
        </div>

        {/* Status Badge */}
        <div className="flex flex-wrap items-center gap-2 text-xs"><RiskBadge level={isExposed ? "critical" : "safe"} /><span>{isExposed ? "Protection required beyond the CRQC horizon" : "Within the security horizon"}</span></div>
      </div>

      {/* Metrics Summary Grid */}
      <div className="mt-5 grid grid-cols-1 sm:grid-cols-4 gap-4 tabular-nums text-xs">
        <div className="p-4 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground normal-case text-xs">Data Shelf-Life (X)</span>
          <span className="text-base font-semibold text-secondary mt-1">{x} Years</span>
          <span className="text-xs text-muted-foreground">Confidentiality requirement</span>
        </div>

        <div className="p-4 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground normal-case text-xs">Migration Effort (Y)</span>
          <span className="text-base font-semibold text-secondary mt-1">{y} Years</span>
          <span className="text-xs text-muted-foreground">PQC transition duration</span>
        </div>

        <div className="p-4 rounded-lg bg-card/60 border border-border flex flex-col justify-between">
          <span className="text-muted-foreground normal-case text-xs"><GlossaryText>{"CRQC Breach Horizon (Z)"}</GlossaryText></span>
          <span className="text-base font-semibold text-secondary mt-1">{z} Years ({startYear + z})</span>
          <span className="text-xs text-muted-foreground"><GlossaryText>{"Estimated CRQC arrival"}</GlossaryText></span>
        </div>

        <div className={`p-4 rounded-lg border flex flex-col justify-between ${isExposed ? "bg-muted border-border text-secondary" : "bg-muted border-border text-secondary"}`}>
          <span className="normal-case text-xs font-semibold">Timeline Balance</span>
          <span className="text-base font-semibold mt-1">
            {isExposed ? `+${deficit.toFixed(1)}y Deficit` : `${(z - totalProtectionNeeded).toFixed(1)}y Margin`}
          </span>
          <span className="text-xs ">
            {isExposed ? "Harvest-now-decrypt-later risk" : "Safe protection window"}
          </span>
        </div>
      </div>

      {/* Interactive Linear Graphic Timeline */}
      <div className="mt-8 overflow-x-auto pt-4 pb-2" role="img" aria-label={`Mosca timeline: migration takes ${y} years, data needs protection for ${x} years, and the estimated CRQC horizon is ${z} years. ${isExposed ? `Protection exceeds the horizon by ${deficit.toFixed(1)} years.` : `Protection stays within the horizon by ${(z - totalProtectionNeeded).toFixed(1)} years.`}`}><div className="min-w-[640px] px-12">
        {/* Top Marker: CRQC Horizon Vertical Pointer */}
        <div className="relative h-6 w-full mb-1">
          <div
            className="absolute top-0 transform -translate-x-1/2 flex flex-col items-center z-20"
            style={{ left: `${zLinePct}%` }}
          >
            <span className="px-2 py-0.5 rounded bg-muted border border-border text-secondary tabular-nums text-xs font-semibold whitespace-nowrap shadow-sm">
              Z = {startYear + z}<GlossaryText>{" CRQC Horizon\n            "}</GlossaryText></span>
          </div>
        </div>

        {/* Duration Track Container */}
        <div className="relative h-12 w-full rounded-xl bg-card border border-border/80 p-1 flex items-center shadow-inner overflow-hidden">
          {/* Stacked Bar 1: Migration Time Y (PQC accent) */}
          <div
            className="qrypton-timeline-y h-full min-w-0 shrink-0 rounded-l-lg flex items-center justify-center text-xs font-semibold overflow-hidden whitespace-nowrap"
            style={{ width: `${yBarWidthPct}%` }}
            title={`PQC Migration Effort Y = ${y} years`}
          >
            Y: Migration ({y}y)
          </div>

          {/* Stacked Bar 2: Data Confidentiality Lifetime X (Slate) */}
          <div
            className="qrypton-timeline-x h-full min-w-0 shrink-0 border-l border-border flex items-center justify-center text-xs font-semibold overflow-hidden whitespace-nowrap"
            style={{ width: `${xBarWidthPct}%` }}
            title={`Confidentiality Lifetime X = ${x} years`}
          >
            X: Data Shelf-Life ({x}y)
          </div>

          {/* Overhang Hazard Segment past Z */}
          {isExposed && (
            <div
              className="qrypton-timeline-overflow absolute top-0 bottom-0 border-y border-r flex items-center justify-center text-xs font-semibold overflow-hidden whitespace-nowrap z-10"
              style={{ left: `${zLinePct}%`, width: `${overhangWidthPct}%` }}
              title={`Quantum Exposure Overhang: +${deficit.toFixed(1)} years`}
            >
              <AlertTriangle className="h-3 w-3 shrink-0" />
              +{deficit.toFixed(1)}y
            </div>
          )}

          {/* Vertical Dashed Line Z (CRQC Arrival Year) */}
          <div
            className="absolute top-0 bottom-0 w-0.5 qrypton-threshold border-r-2 border-dashed border-primary z-30 pointer-events-none"
            style={{ left: `${zLinePct}%` }}
          />
        </div>

        {/* Year Scale Axis Marks */}
        <div className="relative mt-3 h-8 w-full border-t border-border pt-2 tabular-nums text-xs text-muted-foreground">
          {yearTicks.map((yr) => {
            const yrPct = getPct(yr - startYear);
            const isCrqcYear = yr === startYear + z;
            return (
              <div
                key={yr}
                className="absolute top-0 transform -translate-x-1/2 flex flex-col items-center"
                style={{ left: `${yrPct}%` }}
              >
                <div className={`h-2 w-px ${isCrqcYear ? "bg-muted h-3" : "bg-border"}`} />
                <span className={`mt-1 text-xs ${isCrqcYear ? "font-semibold text-secondary" : "text-muted-foreground"}`}>
                  {yr}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      </div>
      {/* Legend & Explanation */}
      <div className="mt-4 pt-4 border-t border-border/60 flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="qrypton-timeline-y h-3 w-3 rounded inline-block" />
            <span>PQC Migration Effort (Y)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="qrypton-timeline-x h-3 w-3 rounded border inline-block" />
            <span>Confidentiality Lifetime (X)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-0.5 border-r-2 border-dashed border-primary inline-block" />
            <span><GlossaryText>{"CRQC Threat Line (Z)"}</GlossaryText></span>
          </div>
        </div>

        <div className="tabular-nums text-xs">
          Theorem: <strong className="text-foreground">X + Y &le; Z</strong> for Quantum Safety
        </div>
      </div>
    </section>
  );
}

export default MoscaLinearTimeline;
