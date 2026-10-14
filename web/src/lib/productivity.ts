import type { CryptoInventoryRow } from "./inventory-view";
export const GLOSSARY: Record<string, string> = {
  CRQC: "A cryptographically relevant quantum computer is powerful enough to break widely used public-key cryptography.",
  Mosca: "Mosca’s rule flags risk when the time data must stay protected plus migration time exceeds the estimated time until a capable quantum computer arrives.",
  "ML-KEM": "ML-KEM is a NIST-standardized post-quantum mechanism for establishing a shared secret key.",
  "ML-DSA": "ML-DSA is a NIST-standardized lattice-based digital signature algorithm designed to resist quantum attacks.",
  "SLH-DSA": "SLH-DSA is a NIST-standardized stateless hash-based digital signature algorithm designed to resist quantum attacks.",
  CBOM: "A cryptographic bill of materials inventories the cryptographic algorithms, keys, certificates, and dependencies used by a system.",
  hybrid: "Hybrid cryptography combines traditional and post-quantum algorithms in a supported protocol during migration.",
};
export function matchesQuickQuery(row: CryptoInventoryRow, query: string): boolean {
  const words = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const text = [row.finding_id, row.algorithm_name, row.algorithm_family, row.application, row.identity_label, row.risk_level, row.category].join(" ").toLowerCase();
  return words.every(word => word === "internet-facing"
    ? row.observations?.exposure?.state === "observed" && row.observations.exposure.value === true
    : text.includes(word));
}
