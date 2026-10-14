export type Observation = { state?: string; value?: unknown; rationale?: string | null; basis_evidence_ids?: string[]; evidence_ids?: string[] };
export function observed(value?: Observation): string {
  if (value?.state !== "observed" || value.value == null) return "Unknown";
  return typeof value.value === "object" ? "Unknown" : String(value.value);
}

export type Timeline = {
  mosca_applicable: "yes" | "no" | "unknown";
  x_data_lifetime_years: number | null; y_migration_years: number | null;
  z_crqc_horizon_years: number | null; required_security_years: number | null;
  time_margin_years: number | null;
};
export function timelineGeometry(t?: Timeline | null) {
  if (!t || t.mosca_applicable !== "yes") return null;
  const { x_data_lifetime_years: x, y_migration_years: y, z_crqc_horizon_years: z, required_security_years: total, time_margin_years: margin } = t;
  if (x == null || y == null || z == null || total == null || margin == null ||
      ![x, y, z, total, margin].every(Number.isFinite) || [x, y, z, total].some(v => v < 0)) return null;
  // Geometry only. The persisted margin and urgency remain authoritative.
  const scale = Math.max(x + y, total, z, 1) * 1.12;
  return { x: x / scale * 100, y: y / scale * 100, z: z / scale * 100,
    overflow: margin < 0 ? Math.max(0, total - z) / scale * 100 : 0 };
}

/** Defense in depth for display metadata; raw excerpts and arbitrary attributes are never rendered. */
export function safeMetadata(value?: string | null): string {
  if (!value) return "Unknown";
  if (/-----BEGIN|(?:password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]|[A-Za-z0-9+/=_-]{48,}/i.test(value)) return "[Sensitive metadata withheld]";
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 1024);
}

export function applicationHref(runId: string, name: string): string {
  return `/?${new URLSearchParams({ id: runId, "iv.q": name, "iv.view": "grouped" })}#inventory`;
}
