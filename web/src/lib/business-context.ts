export type BusinessContext = {
  business_criticality: string;
  data_sensitivity: string;
  data_lifetime: number | null;
  internet_exposure: boolean | null;
};

export const UNKNOWN_CONTEXT: BusinessContext = {
  business_criticality: "unclassified", data_sensitivity: "unclassified",
  data_lifetime: null, internet_exposure: null,
};

// Starting assumptions, always editable; these are not measured risk assessments.
export const BUSINESS_PRESETS: Record<string, BusinessContext> = {
  "Payment gateway": { business_criticality: "critical", data_sensitivity: "restricted", data_lifetime: 7, internet_exposure: true },
  "Internal tool": { business_criticality: "medium", data_sensitivity: "internal", data_lifetime: 1, internet_exposure: false },
  "Patient records": { business_criticality: "critical", data_sensitivity: "restricted", data_lifetime: 30, internet_exposure: false },
  "Public marketing site": { business_criticality: "medium", data_sensitivity: "public", data_lifetime: 1, internet_exposure: true },
};

type SuggestedContext = BusinessContext & Partial<{
  system_name: string; owner: string; environment: string; regulatory_relevance: string;
  migration_complexity: string; migration_time: number; crqc_horizon: number;
}>;

export function parseBusinessContext(value: unknown): SuggestedContext | null {
  if (!value || typeof value !== "object") return null;
  const c = value as Record<string, unknown>;
  if (!["critical", "high", "medium", "low", "unclassified"].includes(String(c.business_criticality))
    || !["restricted", "confidential", "internal", "public", "unclassified"].includes(String(c.data_sensitivity))
    || !(c.internet_exposure === null || typeof c.internet_exposure === "boolean")
    || !(c.data_lifetime === null || (typeof c.data_lifetime === "number" && Number.isFinite(c.data_lifetime) && c.data_lifetime >= 0 && c.data_lifetime <= 10000))) return null;
  const result: SuggestedContext = { business_criticality: String(c.business_criticality), data_sensitivity: String(c.data_sensitivity), data_lifetime: c.data_lifetime as number | null, internet_exposure: c.internet_exposure as boolean | null };
  for (const key of ["system_name", "owner"] as const) {
    if (typeof c[key] === "string" && c[key].length <= 512) result[key] = c[key];
  }
  for (const [key, options] of [
    ["environment", ["production", "staging", "development", "unclassified"]],
    ["regulatory_relevance", ["regulated", "contractual", "none", "unclassified"]],
    ["migration_complexity", ["high", "medium", "low", "unclassified"]],
  ] as const) {
    if (typeof c[key] === "string" && (options as readonly string[]).includes(c[key])) result[key] = c[key];
  }
  for (const key of ["migration_time", "crqc_horizon"] as const) {
    if (typeof c[key] === "number" && Number.isFinite(c[key]) && c[key] >= 0 && c[key] <= 10000) result[key] = c[key];
  }
  return result;
}
