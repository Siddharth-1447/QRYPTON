// Browser-only fixtures. These responses never reach an application database.
const inventory = ['critical', 'high', 'medium', 'low', 'informational', 'unknown'].map((level, index) => ({
  finding_id: `visual-test-${level}`, category: 'source_code', algorithm_name: 'RSA-2048', algorithm_family: 'RSA',
  algorithm_variant: null, crypto_role: 'key_exchange', library_name: 'test-library', identity_status: 'identified',
  identity_label: 'RSA-2048', identification_confidence: 1, usage_confidence: 1, confidence_reasons: [],
  key_size_bits: 2048, lifecycle_status: 'deprecated', risk_level: level, risk_assessment_state: 'assessed',
  business_criticality: 'high', risk_score: 90 - index * 10, confidence: 1, evidence_count: 1,
  first_observed_at: '2026-10-08', last_observed_at: '2026-10-08',
}));
const mosca = inventory.map((item) => ({ finding_id: item.finding_id, urgency: item.risk_level === 'informational' ? 'not_applicable' : item.risk_level }));
const heatmap = ['critical', 'high', 'medium', 'low', 'not_applicable', 'unknown'].flatMap((urgency) => ['low', 'medium', 'high', 'critical', 'unclassified'].map((criticality) => {
  const ids = criticality === 'high' ? mosca.filter((point) => point.urgency === urgency).map((point) => point.finding_id) : [];
  return { mosca_urgency: urgency, business_criticality: criticality, finding_count: ids.length, finding_ids: ids };
}));
const posture = { total_findings: 6, unique_asset_ids: 6, critical_findings_count: 1, high_findings_count: 1, medium_findings_count: 1, low_findings_count: 1, informational_findings_count: 1, unknown_findings_count: 1, unassessed_findings_count: 0, run_status: 'COMPLETED', scanner_failed_count: 0, scanner_partial_count: 0, policy_passed: false, policy_violations: ['Test-only finding'] };
const roadmap = [{ finding_id: inventory[0].finding_id, priority: 1, action: 'Review the test evidence before migration.', role: 'key_exchange', target_algorithms: ['ML-KEM-768'], hybrid_mode: null, blocking_conditions: [], standards_references: [] }];
module.exports = { inventory, posture, roadmap, dashboard: { posture, inventory, mosca, heatmap, roadmap }, detail: { finding: { id: inventory[0].finding_id, category: 'source_code', confidence: 1, identity_label: 'RSA-2048', first_observed_at: '2026-10-08', last_observed_at: '2026-10-08' }, assessment: { level: 'critical' }, business_criticality: 'high', evidence_provenance: [{ id: 'test-evidence', kind: 'source', confidence: 1, location: { relative_path: 'test/crypto.ts', line_start: 1 }, excerpt: 'const algorithm = "RSA-2048";' }], recommendations: [] } };
