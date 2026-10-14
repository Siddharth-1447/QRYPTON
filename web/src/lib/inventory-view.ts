export type KnowledgeState = "observed" | "unknown" | "not_observed" | "confirmed_absent";
export type InventoryObservation = { state: KnowledgeState; value: string | number | boolean | null; rationale?: string | null; evidence_ids?: string[] };
export type InventoryEvidence = { id: string; kind: string; surface: string; location: string | null; confidence: number; excerpt?: string | null };
export type Risk = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type CryptoInventoryRow = {
  finding_id: string; category: string; algorithm_name: string | null; algorithm_family: string | null;
  remediation_rank?: number | null; remediation_reason?: string | null; remediation_ruleset_version?: string | null;
  algorithm_variant: string | null; crypto_role: string | null; library_name: string | null;
  identity_status: string; identity_label: string; identification_confidence: number;
  usage_confidence: number; confidence_reasons: string[]; key_size_bits: number | null;
  lifecycle_status: string | null; quantum_resistant?: boolean; risk_level: Risk;
  risk_assessment_state: "assessed" | "unassessed";
  business_criticality: "critical" | "high" | "medium" | "low" | "unclassified";
  risk_score: number | null; confidence: number; evidence_count: number;
  first_observed_at: string; last_observed_at: string;
  asset_id?: string | null; application?: string | null; artifact_type?: string | null;
  environment?: string | null; source_surfaces?: string[]; observations?: Record<string, InventoryObservation>;
  evidence_rows?: InventoryEvidence[]; quantum_status?: string; quantum_rationale?: string | null;
  timeline_overflow?: boolean | null; mosca_urgency?: string; missing_business_context?: boolean;
  migration_status?: string; assigned_owner?: string | null; in_roadmap?: boolean;
};

export const VIEW_DEFAULTS = {
  application: "", algorithm: "", finding: "",
  q: "", risk: "", family: "", quantum: "", surface: "", criticality: "", environment: "",
  exposure: "", confidence: "", migration: "", urgency: "", context: "", timeline: "",
  view: "grouped", sort: "risk_level", direction: "desc", expanded: [] as string[],
};
export type InventoryViewState = typeof VIEW_DEFAULTS;
export const SORT_KEYS = ["risk_score", "risk_level", "algorithm_name", "last_observed_at", "confidence", "application", "business_criticality", "migration_status", "finding_id"];
export const MIGRATION_STATUSES = ["New", "Reviewed", "Accepted for Migration", "In Progress", "Mitigated", "Verified", "Closed", "Risk Accepted"];
export const PRESET_VIEWS: Record<string, Partial<InventoryViewState>> = {
  "Fix this sprint": { risk: "critical,high", migration: "actionable", sort: "risk_level", direction: "desc" },
  "Internet-facing and X+Y>Z": { exposure: "yes", timeline: "overflow" },
  "Missing business context": { context: "missing" },
};

export function readInventoryView(search: string): InventoryViewState {
  const params = new URLSearchParams(search);
  const state = { ...VIEW_DEFAULTS, expanded: [] as string[] };
  for (const key of Object.keys(VIEW_DEFAULTS) as Array<keyof InventoryViewState>) {
    if (key === "expanded") continue;
    const value = params.get(`iv.${key}`);
    if (value !== null) state[key] = value.slice(0, 512);
  }
  state.view = state.view === "raw" ? "raw" : "grouped";
  state.sort = SORT_KEYS.includes(state.sort) ? state.sort : VIEW_DEFAULTS.sort;
  state.direction = state.direction === "asc" ? "asc" : "desc";
  state.expanded = [...new Set(params.getAll("iv.open"))].slice(0, 5000);
  return state;
}

export function writeInventoryView(search: string, state: InventoryViewState): string {
  const params = new URLSearchParams(search);
  for (const key of [...params.keys()]) if (key.startsWith("iv.")) params.delete(key);
  for (const key of Object.keys(VIEW_DEFAULTS) as Array<keyof InventoryViewState>) {
    if (key === "expanded") continue;
    if (state[key] !== VIEW_DEFAULTS[key]) params.set(`iv.${key}`, state[key]);
  }
  for (const key of [...new Set(state.expanded)].sort()) params.append("iv.open", key);
  return params.toString();
}

export const RISK_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1, unknown: 0 };
export function filterInventory(items: CryptoInventoryRow[], state: InventoryViewState): CryptoInventoryRow[] {
  const query = state.q.trim().toLowerCase();
  return items.filter((row) => {
    const exposure = row.observations?.exposure;
    const haystack = [row.finding_id, row.algorithm_name, row.algorithm_family, row.algorithm_variant, row.crypto_role, row.library_name, row.identity_label, row.category, row.application, row.assigned_owner, ...(row.evidence_rows ?? []).map((e) => `${e.id} ${e.location ?? ""} ${e.kind}`)].join(" ").toLowerCase();
    const missing = row.missing_business_context ?? (row.business_criticality === "unclassified" || !exposure || row.observations?.data_lifetime?.value == null);
    const migration = row.migration_status ?? "New";
    return (!query || haystack.includes(query))
      && (!state.application || (row.application ?? "Unknown") === state.application)
      && (!state.algorithm || (row.algorithm_name ?? "Unknown") === state.algorithm)
      && (!state.finding || row.finding_id === state.finding)
      && (!state.risk || (state.risk === "unassessed" ? row.risk_assessment_state === "unassessed" : row.risk_assessment_state === "assessed" && state.risk.split(",").includes(row.risk_level)))
      && (!state.family || (row.algorithm_family ?? "unknown") === state.family)
      && (!state.quantum || (row.quantum_status ?? "unknown") === state.quantum)
      && (!state.surface || (row.source_surfaces ?? ["unknown"]).includes(state.surface))
      && (!state.criticality || row.business_criticality === state.criticality)
      && (!state.environment || (row.environment ?? "unknown") === state.environment)
      && (!state.exposure || (state.exposure === "unknown" ? !exposure || exposure.state !== "observed" : exposure?.state === "observed" && exposure.value === (state.exposure === "yes")))
      && (!state.confidence || (state.confidence === "high" ? row.confidence >= 0.8 : state.confidence === "medium" ? row.confidence >= 0.5 && row.confidence < 0.8 : state.confidence === "low" ? row.confidence < 0.5 : !Number.isFinite(row.confidence)))
      && (!state.migration || (state.migration === "actionable" ? !["Mitigated", "Verified", "Closed", "Risk Accepted", "migrated", "accepted"].includes(migration) : migration === state.migration))
      && (!state.urgency || row.mosca_urgency === state.urgency)
      && (!state.context || state.context !== "missing" || missing)
      && (!state.timeline || state.timeline !== "overflow" || row.timeline_overflow === true);
  }).sort((a, b) => {
    const key = state.sort as keyof CryptoInventoryRow;
    const direction = state.direction === "asc" ? 1 : -1;
    if (key === "business_criticality") return ((RISK_RANK[a.business_criticality] ?? 0) - (RISK_RANK[b.business_criticality] ?? 0)) * direction || a.finding_id.localeCompare(b.finding_id);
    if (key === "risk_level") return ((RISK_RANK[a.risk_level] ?? 0) - (RISK_RANK[b.risk_level] ?? 0)) * direction || a.finding_id.localeCompare(b.finding_id);
    if (key === "risk_score" || key === "confidence") {
      const av = a[key], bv = b[key];
      if (av == null) return bv == null ? a.finding_id.localeCompare(b.finding_id) : 1;
      if (bv == null) return -1;
      return (av - bv) * direction || a.finding_id.localeCompare(b.finding_id);
    }
    return String(a[key] ?? "").localeCompare(String(b[key] ?? ""), undefined, { numeric: true }) * direction || a.finding_id.localeCompare(b.finding_id);
  });
}

export type InventoryDisplayRow =
  | { kind: "application" | "algorithm"; key: string; label: string; items: CryptoInventoryRow[]; highest: Risk; uncertain: number; evidenceCount: number }
  | { kind: "finding"; key: string; item: CryptoInventoryRow }
  | { kind: "evidence"; key: string; item: CryptoInventoryRow; evidence: InventoryEvidence };

export function buildInventoryRows(items: CryptoInventoryRow[], state: InventoryViewState): InventoryDisplayRow[] {
  const expanded = new Set(state.expanded);
  const results: InventoryDisplayRow[] = [];
  const findings = (rows: CryptoInventoryRow[]) => {
    for (const item of rows) {
      const key = `f:${item.finding_id}`;
      results.push({ kind: "finding", key, item });
      if (expanded.has(key)) for (const evidence of item.evidence_rows ?? []) results.push({ kind: "evidence", key: `${key}:${evidence.id}`, item, evidence });
    }
  };
  if (state.view === "raw") { findings(items); return results; }
  const applications = new Map<string, CryptoInventoryRow[]>();
  for (const item of items) {
    const key = `a:${item.asset_id ?? item.application ?? item.finding_id}`;
    const rows = applications.get(key);
    if (rows) rows.push(item); else applications.set(key, [item]);
  }
  const group = (kind: "application" | "algorithm", key: string, label: string, rows: CryptoInventoryRow[]) => {
    const highest = rows.reduce<Risk>((current, row) => row.risk_assessment_state === "assessed" && RISK_RANK[row.risk_level] > RISK_RANK[current] ? row.risk_level : current, "unknown");
    results.push({ kind, key, label, items: rows, highest,
      uncertain: rows.filter((r) => r.risk_assessment_state === "unassessed" || r.risk_level === "unknown").length,
      evidenceCount: new Set(rows.flatMap((r) => (r.evidence_rows ?? []).map((e) => e.id))).size || rows.reduce((n, r) => n + r.evidence_count, 0) });
  };
  for (const [appKey, rows] of applications) {
    group("application", appKey, rows[0].application ?? `Unknown application · ${rows[0].asset_id ?? rows[0].finding_id}`, rows);
    if (!expanded.has(appKey)) continue;
    const algorithms = new Map<string, CryptoInventoryRow[]>();
    for (const row of rows) {
      const key = `${appKey}:alg:${row.algorithm_family ?? "unknown"}:${row.algorithm_name ?? row.finding_id}`;
      const list = algorithms.get(key);
      if (list) list.push(row); else algorithms.set(key, [row]);
    }
    for (const [key, list] of algorithms) {
      group("algorithm", key, list[0].algorithm_name ?? list[0].identity_label, list);
      if (expanded.has(key)) findings(list);
    }
  }
  return results;
}

export const INVENTORY_ROW_HEIGHT = 84;
export function virtualWindow(count: number, scrollTop: number, height: number, overscan = 4) {
  const start = Math.max(0, Math.floor(scrollTop / INVENTORY_ROW_HEIGHT) - overscan);
  const end = Math.min(count, Math.ceil((scrollTop + height) / INVENTORY_ROW_HEIGHT) + overscan);
  return { start: Math.min(start, count), end, before: Math.min(start, count) * INVENTORY_ROW_HEIGHT, after: Math.max(0, count - end) * INVENTORY_ROW_HEIGHT };
}

export function inventoryCsv(rows: CryptoInventoryRow[], sample = false): string {
  const header = ["data_origin", "finding_id", "algorithm_identity", "identity_status", "family", "variant", "crypto_role", "library", "category", "risk_score", "final_risk_tier", "assessment_state", "business_criticality", "lifecycle_status", "evidence_count", "confidence", "key_size_bits", "mode", "artifact_type", "location_evidence", "application", "environment", "exposure", "data_lifetime_years", "quantum_status", "migration_status", "assigned_owner", "in_roadmap", "first_observed_at", "last_observed_at"];
  const cell = (value: unknown) => {
    const text = String(value ?? "");
    return `"${(/^[=+\-@\t\r]/.test(text) ? "'" + text : text).replaceAll('"', '""')}"`;
  };
  return [header.join(","), ...rows.map((r) => [sample ? "Sample data" : "", r.finding_id, r.algorithm_name ?? r.identity_label, r.identity_status, r.algorithm_family, r.algorithm_variant, r.crypto_role, r.library_name, r.category, r.risk_score, r.risk_level, r.risk_assessment_state, r.business_criticality, r.lifecycle_status, r.evidence_count, r.confidence, r.key_size_bits, r.observations?.mode?.value, r.artifact_type, (r.evidence_rows ?? []).map((e) => `${e.id}: ${e.location ?? "not observed"}`).join("; "), r.application, r.environment, r.observations?.exposure?.state === "observed" ? r.observations.exposure.value : r.observations?.exposure?.state ?? "unknown", r.observations?.data_lifetime?.value, r.quantum_status ?? "unknown", r.migration_status ?? "untriaged", r.assigned_owner, r.in_roadmap ?? false, r.first_observed_at, r.last_observed_at].map(cell).join(","))].join("\n");
}
