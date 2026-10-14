import { filterInventory, RISK_RANK, type CryptoInventoryRow, type InventoryViewState } from "./inventory-view";

export const URGENCIES = ["critical", "high", "medium", "low", "not_applicable", "unknown"] as const;
export const CRITICALITIES = ["low", "medium", "high", "critical", "unclassified"] as const;
export type HeatmapCell = { mosca_urgency: string; business_criticality: string; finding_count: number; finding_ids: string[] };
export type CellSelection = { urgency: string; criticality: string; finding_ids?: string[] };

export function riskView(cells: HeatmapCell[], inventory: CryptoInventoryRow[], state: InventoryViewState, selected: CellSelection | null) {
  const base = filterInventory(inventory, selected ? { ...state, urgency: "", criticality: "" } : state);
  const available = new Map(base.map(row => [row.finding_id, row]));
  const projected = cells.map(cell => {
    const rows = cell.finding_ids.flatMap(id => available.has(id) ? [available.get(id)!] : []);
    const applications = new Map<string, number>();
    for (const row of rows) applications.set(row.application ?? "Unknown", (applications.get(row.application ?? "Unknown") ?? 0) + 1);
    const top = [...applications].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
    const highest = rows.reduce((risk, row) => Math.max(risk, row.risk_assessment_state === "assessed" ? RISK_RANK[row.risk_level] ?? 0 : 0), 0);
    return { ...cell, finding_count: rows.length, finding_ids: rows.map(r => r.finding_id), topApplication: top?.[0] ?? "None", highestRisk: highest };
  });
  const selectedIds = selected ? new Set(projected
    .filter(c => c.mosca_urgency === selected.urgency && (!selected.criticality || c.business_criticality === selected.criticality))
    .flatMap(c => c.finding_ids)) : null;
  const findings = base.filter(row => !selectedIds || selectedIds.has(row.finding_id)).sort((a, b) => (a.remediation_rank ?? Infinity) - (b.remediation_rank ?? Infinity) || a.finding_id.localeCompare(b.finding_id));
  const assigned = projected.flatMap(c => c.finding_ids);
  return { cells: projected, findings, total: base.length, valid: assigned.length === base.length && new Set(assigned).size === base.length };
}

export function nextCell(index: number, key: string): number {
  const row = Math.floor(index / 5), column = index % 5;
  if (key === "ArrowRight") return row * 5 + (column + 1) % 5;
  if (key === "ArrowLeft") return row * 5 + (column + 4) % 5;
  if (key === "ArrowDown") return ((row + 1) % 6) * 5 + column;
  if (key === "ArrowUp") return ((row + 5) % 6) * 5 + column;
  if (key === "Home") return row * 5;
  if (key === "End") return row * 5 + 4;
  return index;
}
