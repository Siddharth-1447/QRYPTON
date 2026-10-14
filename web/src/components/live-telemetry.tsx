"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import {
  Activity,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
  KeyRound,
  Pause,
  Play,
  Gauge,
} from "lucide-react";

import { Badge } from "@/components/ui/primitives";
import { TelemetryChart } from "@/components/telemetry-chart";

type Classification = "vulnerable" | "compliant" | "deprecated";

interface StreamRow {
  id: number;
  ts: string;
  host: string;
  alg: string;
  keyLabel: string;
  status: Classification;
}

// Synthetic catalog for the explicitly labelled interface preview.
const CATALOG: Array<{ alg: string; keyLabel: string; status: Classification }> = [
  { alg: "RSA-2048", keyLabel: "2048-bit", status: "vulnerable" },
  { alg: "RSA-4096", keyLabel: "4096-bit", status: "vulnerable" },
  { alg: "ECDSA-P256", keyLabel: "256-bit", status: "vulnerable" },
  { alg: "ECDH-P384", keyLabel: "384-bit", status: "vulnerable" },
  { alg: "SHA-1", keyLabel: "160-bit", status: "deprecated" },
  { alg: "3DES-CBC", keyLabel: "168-bit", status: "deprecated" },
  { alg: "ML-KEM-768", keyLabel: "L3 · FIPS 203", status: "compliant" },
  { alg: "ML-KEM-1024", keyLabel: "L5 · FIPS 203", status: "compliant" },
  { alg: "ML-DSA-65", keyLabel: "L3 · FIPS 204", status: "compliant" },
  { alg: "AES-256-GCM", keyLabel: "256-bit", status: "compliant" },
];

const HOSTS = [
  "*.qrypton.io",
  "vault.qrypton.io",
  "api-gw.payments.internal",
  "edge-tls-07.qrypton.io",
  "kms.us-east-1.aws",
  "mesh-sidecar-42.svc",
  "ldap.corp.local",
  "cdn-node-19.qrypton.io",
  "auth.qrypton.io",
  "db-primary.payments.internal",
];

const BAR_COUNT = 28;



function formatTs(date: Date) {
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  const ss = String(date.getSeconds()).padStart(2, "0");
  const ms = String(date.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

export function LiveTelemetry() {
  const [mounted] = useState(true);
  const [running, setRunning] = useState(true);
  const [rows, setRows] = useState<StreamRow[]>([]);
  const [keysScanned, setKeysScanned] = useState(48213);
  const [violations, setViolations] = useState(1174);
  const [tunnels, setTunnels] = useState(326);
  const [target, setTarget] = useState(HOSTS[0]);
  const [throughput, setThroughput] = useState<number[]>(() =>
    Array.from({ length: BAR_COUNT }, () => 30)
  );

  const idRef = useRef(0);
  const tick = useCallback(() => {
    const entry = CATALOG[Math.floor(Math.random() * CATALOG.length)];
    const host = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    const now = new Date();
    idRef.current += 1;

    const row: StreamRow = {
      id: idRef.current,
      ts: formatTs(now),
      host,
      alg: entry.alg,
      keyLabel: entry.keyLabel,
      status: entry.status,
    };

    setTarget(host);
    setRows((prev) => [row, ...prev].slice(0, 24));
    setKeysScanned((prev) => prev + Math.floor(Math.random() * 7) + 3);
    if (entry.status === "vulnerable") {
      setViolations((prev) => prev + 1);
    }
    if (entry.status === "compliant" && entry.alg.startsWith("ML-")) {
      setTunnels((prev) => prev + (Math.random() > 0.5 ? 1 : 0));
    }
    setThroughput((prev) => {
      const nextVal = 20 + Math.floor(Math.random() * 80);
      return [...prev.slice(1), nextVal];
    });
  }, []);

  useEffect(() => {
    if (!running) return;
    const initialTick = window.setTimeout(tick, 0);
    const interval = setInterval(tick, 1400);
    return () => {
      window.clearTimeout(initialTick);
      clearInterval(interval);
    };
  }, [running, tick]);

  return (
    <section id="live-scanner" aria-labelledby="live-scanner-heading" className="space-y-4">
      <div role="status" className="qrypton-simulated-banner">
        SIMULATED DATA — sample mode; no network traffic was inspected
      </div>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2
            id="live-scanner-heading"
            className="mt-1 flex items-center gap-2 text-xl font-semibold tracking-normal"
          >
            <Radio className="size-5 text-secondary" aria-hidden="true" />
            Network Inspection Preview
          </h2>
          <p className="mt-1 text-sm leading-6 text-muted-foreground">
            Simulated handshake activity previews the inspection interface. These values are not measured network traffic.
          </p>
        </div>
        <div className="flex items-center gap-4">
          <span
            className={`inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-xs font-semibold ${
              running ? "bg-muted text-secondary" : "bg-muted text-secondary"
            }`}
          >
            <span
              className={`size-1.5 rounded-full bg-current ${running ? "" : ""}`}
              aria-hidden="true"
            />
            {running ? "Demo running" : "Demo paused"}
          </span>
          <button
            type="button"
            onClick={() => setRunning((prev) => !prev)}
            className="inline-flex min-h-10 items-center gap-2 rounded-md border border-border bg-card px-4 text-sm font-semibold text-foreground qrypton-motion hover:bg-muted"
          >
            {running ? (
              <>
                <Pause className="size-4" aria-hidden="true" />
                Pause
              </>
            ) : (
              <>
                <Play className="size-4" aria-hidden="true" />
                Resume
              </>
            )}
          </button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Live scanner inspection panel */}
        <div className="qrypton-card flex flex-col gap-4 p-6 lg:col-span-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity
                className={`size-4 text-secondary ${running ? "" : ""}`}
                aria-hidden="true"
              />
              <span className="text-sm font-semibold">Network inspection</span>
            </div>
            <span className="flex items-center gap-1.5 tabular-nums text-xs text-muted-foreground">
              <Gauge className="size-3.5" aria-hidden="true" />
              {mounted ? `${(throughput[throughput.length - 1] * 4.2).toFixed(0)} handshakes/s` : "—"}
            </span>
          </div>
          <p className="-mt-2 text-xs leading-5 text-muted-foreground">
            Example TLS handshakes illustrate algorithm classification and key strength.
            This preview is separate from your persisted scan findings.
          </p>

          {/* Sample endpoint target */}
          <div className="flex items-center justify-between rounded-md border border-border bg-muted/40 px-4 py-4">
            <div>
              <p className="text-xs font-semibold normal-case tracking-normal text-muted-foreground">
                Sample endpoint
              </p>
              <p className="mt-0.5 tabular-nums text-sm font-semibold text-foreground">
                {mounted ? target : "initializing…"}
              </p>
            </div>
            <span className="tabular-nums text-xs text-muted-foreground">TLS 1.3 · handshake</span>
          </div>

          <TelemetryChart samples={throughput} running={running} />
        </div>

        {/* Telemetry tickers */}
        <div className="flex flex-col gap-4">
          <TickerCard
            icon={<KeyRound className="size-4" aria-hidden="true" />}
            label="Sample keys classified"
            value={mounted ? keysScanned.toLocaleString() : "—"}
            tone="neutral"
            caption="Simulated session total"
          />
          <TickerCard
            icon={<ShieldAlert className="size-4" aria-hidden="true" />}
            label="Sample exposure flags"
            value={mounted ? violations.toLocaleString() : "—"}
            tone="critical"
            caption="Simulated vulnerable observations"
          />
          <TickerCard
            icon={<ShieldCheck className="size-4" aria-hidden="true" />}
            label="Sample PQC sessions"
            value={mounted ? tunnels.toLocaleString() : "—"}
            tone="success"
            caption="Simulated ML-KEM / ML-DSA activity"
          />
        </div>
      </div>

      {/* Data stream log */}
      <div className="qrypton-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-border p-6">
          <div className="flex items-center gap-2">
            <Waypoints className="size-4 text-secondary" aria-hidden="true" />
            <h3 className="text-base font-semibold">Classification Data Stream</h3>
          </div>
          <span className="tabular-nums text-xs text-muted-foreground">
            {mounted ? `${rows.length} events buffered` : "standby"}
          </span>
        </div>
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full border-collapse text-left tabular-nums text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="text-xs normal-case tracking-normal text-muted-foreground">
                <th className="px-6 py-4 font-semibold">Timestamp</th>
                <th className="px-6 py-4 font-semibold">Asset</th>
                <th className="px-6 py-4 font-semibold">Algorithm</th>
                <th className="hidden px-6 py-4 font-semibold sm:table-cell">Key</th>
                <th className="px-6 py-4 text-right font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-muted-foreground">
                    {mounted ? "Awaiting first classified handshake…" : "Scanner on standby"}
                  </td>
                </tr>
              ) : (
                rows.map((row, index) => {
                  return (
                    <tr
                      key={`${row.id}-${index}`}
                      className={`text-foreground ${index === 0 ? "" : ""}`}
                    >
                      <td className="whitespace-nowrap px-6 py-2.5 text-muted-foreground">
                        {row.ts}
                      </td>
                      <td className="whitespace-nowrap px-6 py-2.5 font-mono font-semibold">{row.host}</td>
                      <td className="whitespace-nowrap px-6 py-2.5 font-mono">{row.alg}</td>
                      <td className="hidden whitespace-nowrap px-6 py-2.5 font-mono text-muted-foreground sm:table-cell">
                        {row.keyLabel}
                      </td>
                      <td className="whitespace-nowrap px-6 py-2.5 text-right">
                        <Badge>{row.status === "compliant" ? <ShieldCheck className="size-3" aria-hidden="true" /> : <ShieldAlert className="size-3" aria-hidden="true" />}{row.status === "vulnerable" ? "Vulnerable" : row.status === "deprecated" ? "Deprecated" : "PQC Compliant"}</Badge>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function TickerCard({
  icon,
  label,
  value,
  caption,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  caption: string;
  tone: "neutral" | "critical" | "success";
}) {
  const valueTone =
    tone === "critical"
      ? "text-secondary"
      : tone === "success"
        ? "text-secondary"
        : "text-foreground";
  const iconTone =
    tone === "critical"
      ? "bg-muted text-secondary"
      : tone === "success"
        ? "bg-muted text-secondary"
        : "bg-muted text-secondary";

  return (
    <div className="qrypton-card flex flex-1 flex-col justify-between gap-4 p-6">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold normal-case tracking-normal text-muted-foreground">
          {label}
        </span>
        <span className={`rounded-md p-2 ${iconTone}`}>{icon}</span>
      </div>
      <div>
        <p className={`tabular-nums text-3xl font-semibold tabular-nums ${valueTone}`}>{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{caption}</p>
      </div>
    </div>
  );
}
