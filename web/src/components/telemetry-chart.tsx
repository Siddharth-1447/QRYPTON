
/** Presentation only: values come from the parent's explicitly labelled demo stream. */
export function TelemetryChart({ samples, running }: { samples: number[]; running: boolean }) {
  const rates = samples.map((sample) => Math.round(sample * 4.2));
  const current = rates.at(-1) ?? 0;
  const average = rates.length ? Math.round(rates.reduce((sum, rate) => sum + rate, 0) / rates.length) : 0;
  const peak = Math.max(0, ...rates);
  const points = rates.map((rate, index) => ({
    x: index * 640 / Math.max(1, rates.length - 1),
    y: 184 - Math.min(450, Math.max(0, rate)) / 450 * 168,
  }));
  const line = points.map((point, index) => {
    if (!index) return `M ${point.x} ${point.y}`;
    const previous = points[index - 1];
    const middle = (previous.x + point.x) / 2;
    return `C ${middle} ${previous.y}, ${middle} ${point.y}, ${point.x} ${point.y}`;
  }).join(" ");

  return <div className="mt-auto overflow-hidden rounded-xl border border-border  /[0.04] ">
    <div className="flex flex-wrap items-end justify-between gap-4 px-6 pt-6">
      <div>
        <p className="text-xs font-semibold normal-case tracking-normal text-muted-foreground">Handshake throughput</p>
        <p className="mt-1 flex items-baseline gap-2"><span className="text-3xl font-semibold tabular-nums tracking-normal">{current}</span><span className="text-xs text-muted-foreground">/ second</span></p>
      </div>
      <dl className="flex gap-6 text-xs"><div><dt className="text-muted-foreground">Average</dt><dd className="mt-1 font-semibold tabular-nums">{average} <span className="font-normal text-muted-foreground">/s</span></dd></div><div><dt className="text-muted-foreground">Peak</dt><dd className="mt-1 font-semibold tabular-nums">{peak} <span className="font-normal text-muted-foreground">/s</span></dd></div></dl>
    </div>
    <div className="relative mx-5 mt-4 pl-8">
      <div className="absolute bottom-0 left-0 top-0 flex flex-col justify-between py-4 text-xs tabular-nums text-muted-foreground" aria-hidden="true"><span>450</span><span>225</span><span>0</span></div>
      <svg className="h-48 w-full" viewBox="0 0 640 200" preserveAspectRatio="none" role="img" aria-label={`Simulated handshake throughput: ${current} per second, average ${average}, peak ${peak}`}>
        {[16, 100, 184].map((y) => <line key={y} x1="0" y1={y} x2="640" y2={y} stroke="currentColor" strokeOpacity=".12" strokeDasharray="3 6" vectorEffect="non-scaling-stroke" />)}
        {points.length > 0 && <><path d={`${line} L ${points.at(-1)!.x} 184 L 0 184 Z`} fill="var(--surface-subtle)" /><path d={line} fill="none" stroke="var(--text-secondary)" strokeWidth="2" strokeLinecap="round" vectorEffect="non-scaling-stroke" /></>}
      </svg>
      <div className="flex justify-between pb-4 text-xs tabular-nums text-muted-foreground"><span>−{Math.round(Math.max(0, samples.length - 1) * 1.4)}s</span><span>Rolling sample window</span><span>Now</span></div>
    </div>
    <div className="flex items-center justify-between gap-4 border-t border-border/60 px-6 py-4 text-xs text-muted-foreground"><span className="flex items-center gap-2"><span className={`size-1.5 rounded-full ${running ? "bg-muted" : "bg-muted"}`} />{running ? "Updating every 1.4 seconds" : "Simulation paused"}</span><span>SIMULATED DATA</span></div>
  </div>;
}
