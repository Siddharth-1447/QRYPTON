import { cn } from "@/lib/utils";

/** Q mark and lockup share the existing theme tokens in both palettes. */
export function Logo({ tone = "on-dark", lockup = false, tagline, className }: {
  tone?: "on-dark" | "default";
  lockup?: boolean;
  tagline?: string;
  className?: string;
}) {
  return <span data-logo-tone={tone} className={cn("inline-flex items-center gap-2", className)} aria-label="QRYPTON">
    <svg viewBox="0 0 24 24" className="h-full w-auto shrink-0" aria-hidden="true">
      <polygon points="12,2.5 20.5,7.2 20.5,15.5 12,21 3.5,15.5 3.5,7.2" fill="none" stroke="var(--logo-frame)" strokeWidth="3.6" strokeLinejoin="round" />
      <polygon points="13,14.5 19,18.5 19,23 13,19" fill="var(--logo-tail)" />
    </svg>
    {lockup && <span className="min-w-0 flex-1 leading-tight"><span className="qrypton-wordmark block truncate text-lg font-semibold text-foreground">RYPTON</span>{tagline && <span className="block truncate text-xs text-muted-foreground">{tagline}</span>}</span>}
  </span>;
}

export function Wordmark({ className }: { className?: string }) {
  return <span aria-label="QRYPTON" className={cn("qrypton-brand-wordmark", className)}><span aria-hidden="true" className="inline-flex items-center"><Logo className="qrypton-brand-initial" /><span>RYPTON</span></span></span>;
}
