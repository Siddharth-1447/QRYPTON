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

type Classification = "vulnerable" | "compliant" | "deprecated";

interface StreamRow {
  id: number;
  ts: string;
  host: string;
  alg: string;
  keyLabel: string;
  status: Classification;
}

// Fixed catalog of algorithms the live scanner classifies as it inspects traffic.
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

const STATUS_META: Record<Classification, { label: string; dot: string; text: string }> = {
  vulnerable: { label: "Vulnerable", dot: "bg-red-500", text: "text-red-500" },
  compliant: { label: "PQC Compliant", dot: "bg-emerald-400", text: "text-emerald-400" },
  deprecated: { label: "Deprecated", dot: "bg-amber-500", text: "text-amber-500" },
};

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
    tick();
    const interval = setInterval(tick, 1400);
    return () => clearInterval(interval);
  }, [running, tick]);

  return (
    <section id="live-scanner" aria-labelledby="live-scanner-heading" className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2
            id="live-scanner-heading"
            className="mt-1 flex items-center gap-2 text-xl font-semibold tracking-tight"
          >
            <Radio className="size-5 text-primary" aria-hidden="true" />
            Live Cryptographic Scanner
          </h2>
          <p className="mt-1 text-sm leading-6 text-muted-foreground">
            Continuous inspection of network traffic, classifying every handshake against
            post-quantum readiness in real time.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-xs font-semibold ${
              running ? "qrypton-risk-success" : "qrypton-risk-medium"
            }`}
          >
            <span
              className={`size-1.5 rounded-full bg-current ${running ? "animate-pulse" : ""}`}
              aria-hidden="true"
            />
            {running ? "Live" : "Paused"}
          </span>
          <button
            type="button"
            onClick={() => setRunning((prev) => !prev)}
            className="inline-flex min-h-9 items-center gap-2 rounded-md border border-border bg-card px-3 text-sm font-semibold text-foreground transition-colors hover:bg-muted"
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
        <div className="qrypton-card flex flex-col gap-4 p-5 lg:col-span-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity
                className={`size-4 text-primary ${running ? "animate-pulse" : ""}`}
                aria-hidden="true"
              />
              <span className="text-sm font-semibold">Network inspection</span>
            </div>
            <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
              <Gauge className="size-3.5" aria-hidden="true" />
              {mounted ? `${(throughput[throughput.length - 1] * 4.2).toFixed(0)} handshakes/s` : "—"}
            </span>
          </div>
          <p className="-mt-2 text-xs leading-5 text-muted-foreground">
            This panel samples TLS handshakes to identify the negotiated algorithm, key strength,
            and PQC readiness before the connection is relied on by a service. It provides a
            live operational signal alongside the persisted artifact scan results.
          </p>

          {/* Currently inspecting target */}
          <div className="flex items-center justify-between rounded-md border border-border bg-muted/40 px-4 py-3">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Currently inspecting
              </p>
              <p className="mt-0.5 font-mono text-sm font-semibold text-foreground">
                {mounted ? target : "initializing…"}
              </p>
            </div>
            <span className="font-mono text-xs text-muted-foreground">TLS 1.3 · handshake</span>
          </div>

          {/* Clean enterprise throughput telemetry graph */}
          <div className="relative rounded-md border border-border bg-card/50 p-4">
            <div className="flex h-20 items-end gap-1">
{throughput.map((value, index) => (
                  <div
                    key={`${value}-${index}`}
                  className="flex-1 rounded-sm bg-emerald-500/30 border-t border-emerald-400/60 transition-all duration-300"
                  style={{ height: `${mounted ? value : 24}%` }}
                />
              ))}
            </div>
            <div className="mt-3 flex items-center justify-between font-mono text-[10px] uppercase text-muted-foreground border-t border-border/60 pt-2">
              <span>Cryptographic Handshake Rate</span>
              <span>Rolling telemetry window</span>
            </div>
          </div>
        </div>

        {/* Telemetry tickers */}
        <div className="flex flex-col gap-4">
          <TickerCard
            icon={<KeyRound className="size-4" aria-hidden="true" />}
            label="Live Keys Scanned"
            value={mounted ? keysScanned.toLocaleString() : "—"}
            tone="neutral"
            caption="Cumulative this session"
          />
          <TickerCard
            icon={<ShieldAlert className="size-4" aria-hidden="true" />}
            label="CRQC Threshold Violations"
            value={mounted ? violations.toLocaleString() : "—"}
            tone="critical"
            caption="Quantum-vulnerable assets"
          />
          <TickerCard
            icon={<ShieldCheck className="size-4" aria-hidden="true" />}
            label="Active PQC Tunnels"
            value={mounted ? tunnels.toLocaleString() : "—"}
            tone="success"
            caption="ML-KEM / ML-DSA protected"
          />
        </div>
      </div>

      {/* Data stream log */}
      <div className="qrypton-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-border p-5">
          <div className="flex items-center gap-2">
            <Waypoints className="size-4 text-primary" aria-hidden="true" />
            <h3 className="text-base font-semibold">Classification data stream</h3>
          </div>
          <span className="font-mono text-xs text-muted-foreground">
            {mounted ? `${rows.length} events buffered` : "standby"}
          </span>
        </div>
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full border-collapse text-left font-mono text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-5 py-3 font-semibold">Timestamp</th>
                <th className="px-5 py-3 font-semibold">Asset</th>
                <th className="px-5 py-3 font-semibold">Algorithm</th>
                <th className="hidden px-5 py-3 font-semibold sm:table-cell">Key</th>
                <th className="px-5 py-3 text-right font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center text-muted-foreground">
                    {mounted ? "Awaiting first classified handshake…" : "Scanner on standby"}
                  </td>
                </tr>
              ) : (
                rows.map((row, index) => {
                  const meta = STATUS_META[row.status];
                  return (
                    <tr
                      key={`${row.id}-${index}`}
                      className={`text-foreground ${index === 0 ? "qrypton-rowin" : ""}`}
                    >
                      <td className="whitespace-nowrap px-5 py-2.5 text-muted-foreground">
                        {row.ts}
                      </td>
                      <td className="whitespace-nowrap px-5 py-2.5 font-semibold">{row.host}</td>
                      <td className="whitespace-nowrap px-5 py-2.5">{row.alg}</td>
                      <td className="hidden whitespace-nowrap px-5 py-2.5 text-muted-foreground sm:table-cell">
                        {row.keyLabel}
                      </td>
                      <td className="whitespace-nowrap px-5 py-2.5 text-right">
                        <span className={`inline-flex items-center gap-1.5 font-semibold ${meta.text}`}>
                          <span className={`size-1.5 rounded-full ${meta.dot}`} aria-hidden="true" />
                          {meta.label}
                        </span>
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
      ? "text-red-500"
      : tone === "success"
        ? "text-emerald-400"
        : "text-foreground";
  const iconTone =
    tone === "critical"
      ? "qrypton-risk-critical"
      : tone === "success"
        ? "qrypton-risk-success"
        : "bg-muted text-primary";

  return (
    <div className="qrypton-card flex flex-1 flex-col justify-between gap-3 p-5">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <span className={`rounded-md p-2 ${iconTone}`}>{icon}</span>
      </div>
      <div>
        <p className={`font-mono text-3xl font-bold tabular-nums ${valueTone}`}>{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{caption}</p>
      </div>
    </div>
  );
}
