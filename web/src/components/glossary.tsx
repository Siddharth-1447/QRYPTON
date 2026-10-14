"use client";
import { useId, useState } from "react";
import { createPortal } from "react-dom";
import { GLOSSARY } from "@/lib/productivity";

function GlossaryTerm({ term, label }: { term: string; label: string }) {
  const id = useId();
  const [position, setPosition] = useState<{left: number; top: number} | null>(null);
  const reveal = (element: HTMLElement) => {
    const rect = element.getBoundingClientRect();
    setPosition({left: Math.max(12, Math.min(rect.left, innerWidth - 312)), top: rect.bottom + 120 < innerHeight ? rect.bottom + 6 : Math.max(12, rect.top - 110)});
  };
  return <span className="glossary-term" tabIndex={0} aria-describedby={position ? id : undefined}
    onMouseEnter={e => reveal(e.currentTarget)} onMouseLeave={() => setPosition(null)}
    onFocus={e => reveal(e.currentTarget)} onBlur={() => setPosition(null)}
    onKeyDown={e => { if (e.key === "Escape") { e.stopPropagation(); setPosition(null); } }}>
    {label}{position && createPortal(<span id={id} role="tooltip" style={{position: "fixed", ...position, zIndex: 120, width: "min(300px, 80vw)"}} className="pointer-events-none rounded-lg border border-border bg-background p-3 text-sm font-normal leading-6 text-foreground shadow-lg">{GLOSSARY[term]}</span>, document.body)}
  </span>;
}
export function GlossaryText({ children }: { children: string }) {
  return <>{children.split(/\b(CRQC|Mosca|ML-KEM|ML-DSA|SLH-DSA|CBOM|hybrid)\b/gi).map((part, i) => {
    const term = Object.keys(GLOSSARY).find(key => key.toLowerCase() === part.toLowerCase());
    return term ? <GlossaryTerm key={i} term={term} label={part} /> : part;
  })}</>;
}
