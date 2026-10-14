"use client";

import { Wordmark } from "./logo";

import { GlossaryText } from "@/components/glossary";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Check, Play } from "lucide-react";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input, RiskBadge, type RiskLevel } from "@/components/ui/primitives";
import { useMotionDuration } from "@/lib/motion";
import { MoscaLinearTimeline } from "@/components/mosca-timeline";
import { ScanProgress } from "@/components/scan-progress";
import type { ScanStatus } from "@/lib/scan-polling";

export function DesignReference() {
  const [confirmed, setConfirmed] = useState(false);
  const [scanPreview, setScanPreview] = useState<ScanStatus | null>(null);
  const duration = useMotionDuration();
  const levels: RiskLevel[] = ["critical", "high", "medium", "low", "safe", "unknown", "informational", "unassessed"];
  return <main className="mx-auto flex w-full max-w-5xl flex-col gap-8 p-6">
    <header><Link href="/" className="inline-flex items-center gap-2 text-primary"><ArrowLeft className="size-4" /><Wordmark /></Link><h1 className="mt-4 text-2xl font-semibold">Design Reference</h1><Badge>Development only</Badge></header>
    <section className="space-y-4" aria-label="Typography"><h2 className="text-xl font-semibold">Typography</h2>{[12, 13, 14, 16, 20, 28, 40].map((size) => <p key={size} style={{ fontSize: `var(--type-${size})` }}>{size} / Cryptographic inventory</p>)}<p className="font-mono"><GlossaryText>{"RSA-2048 / ML-KEM-768 / src/crypto.ts"}</GlossaryText></p></section>
    <section className="space-y-4"><h2 className="text-xl font-semibold">Risk</h2><div className="flex flex-wrap gap-4">{levels.map((level) => <RiskBadge key={level} level={level} />)}</div><div className="overflow-x-auto"><table className="w-full text-left"><thead><tr><th>Risk</th><th>Next action</th></tr></thead><tbody>{levels.map((level) => <tr key={level} data-risk={level}><td><RiskBadge level={level} /></td><td>Review evidence</td></tr>)}</tbody></table></div></section>
    <section className="space-y-4"><h2 className="text-xl font-semibold">Actions</h2><div className="flex flex-wrap gap-4"><Button>Review inventory</Button><Button variant="secondary">Export</Button><Button variant="ghost">Cancel</Button><Button disabled>Unavailable</Button></div><label className="block max-w-sm space-y-2"><span>Algorithm</span><Input placeholder="Search algorithms" /></label></section>
    <Card><CardHeader><CardTitle>Evidence Review</CardTitle></CardHeader><CardContent><p className="text-muted-foreground">No workspace data is loaded on this reference page.</p></CardContent></Card>
    <section className="space-y-4"><h2 className="text-xl font-semibold">Motion</h2><p>Fast: 120ms / Base: 200ms / Hero specification: 600ms (active cap: 250ms)</p><p>Active duration: <output data-testid="motion-duration">{duration}</output>ms</p><Button variant="secondary" onClick={() => setConfirmed((value) => !value)}><Play className="size-4" />Toggle confirmation</Button><div className="flex h-10 items-center"><span data-testid="motion-preview" className="qrypton-motion inline-flex items-center gap-2" style={{ opacity: confirmed ? 1 : 0, transform: confirmed ? "translateY(0)" : "translateY(8px)", transitionDuration: `${duration}ms` }}><Check className="size-4" />Confirmed</span></div></section>
    <section className="space-y-4"><h2 className="text-xl font-semibold"><GlossaryText>{"Mosca timeline / illustrative inputs"}</GlossaryText></h2><MoscaLinearTimeline xDataLifetime={7} yMigrationYears={4} zCrqcHorizon={8} /></section>
    <section className="space-y-4" aria-label="Scan presentation preview"><h2 className="text-xl font-semibold">Scan Workflow / Illustrative Telemetry</h2><div className="flex flex-wrap gap-2">
      <Button variant="secondary" onClick={() => setScanPreview(null)}>Preview waiting</Button>
      <Button variant="secondary" onClick={() => setScanPreview({ status: "RUNNING", findings_discovered: 12, stages: ["completed", "completed", "running", "pending", "pending", "pending", "pending", "pending"] })}>Preview running</Button>
      <Button variant="secondary" onClick={() => setScanPreview({ status: "COMPLETED", findings_discovered: 24, stages: Array(8).fill("completed") })}>Preview complete</Button>
      <Button variant="secondary" onClick={() => setScanPreview({ status: "PARTIAL", findings_discovered: 18, stages: ["completed", "completed", "warning", "completed", "completed", "completed", "completed", "completed"] })}>Preview partial</Button>
      <Button variant="secondary" onClick={() => setScanPreview({ status: "FAILED", stages: ["completed", "failed", "pending", "pending", "pending", "pending", "pending", "pending"] })}>Preview failed</Button>
    </div><ScanProgress progress={scanPreview} /></section>
  </main>;
}
