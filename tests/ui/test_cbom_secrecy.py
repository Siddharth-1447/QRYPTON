"""CBOM keeps provenance and uncertainty while excluding captured secrets."""

from __future__ import annotations

import json

from qrypton.exporters.cyclonedx_1_6 import CycloneDx16CbomExporter, sanitize_persisted_cbom
from tests.ui.conftest import sample_evidence, sample_finding


def test_cbom_component_excludes_freeform_secrets_and_keeps_provenance():
    tenant = "tenant_" + "a" * 52
    asset = "asset_" + "a" * 52
    target = "target_" + "a" * 52
    evidence_id = "evidence_" + "b" * 52
    finding_id = "finding_" + "b" * 52
    evidence = sample_evidence(evidence_id, tenant, asset, target).model_copy(
        update={"excerpt": "PRIVATE KEY RAW SECRET", "attributes": {"token": "SECRET-ATTRIBUTE"}}
    )
    finding = sample_finding(finding_id, tenant, asset, target, evidence_id)
    algorithm = finding.algorithm.value.model_copy(
        update={"parameters": {"mode": "gcm", "private_key": "SECRET-PARAMETER"}}
    )
    finding = finding.model_copy(
        update={"algorithm": finding.algorithm.model_copy(update={"value": algorithm})}
    )
    exporter = CycloneDx16CbomExporter()
    component = exporter._finding_component(finding, None, (), None, {evidence.id: evidence}, asset)
    encoded = json.dumps(component)
    assert "PRIVATE KEY RAW SECRET" not in encoded
    assert "SECRET-ATTRIBUTE" not in encoded
    assert "SECRET-PARAMETER" not in encoded
    properties = {item["name"]: item["value"] for item in component["properties"]}
    canonical = json.loads(properties["org.qrypton.finding.canonical"])
    assert canonical["algorithm"]["value"]["parameters"] == {"mode": "gcm"}
    exported_evidence = json.loads(properties["org.qrypton.evidence"])
    assert exported_evidence["id"] == evidence_id
    assert exported_evidence["provenance"]["scanner_name"] == "qrypton-test-scanner"


def test_legacy_download_projection_redacts_secrets_without_losing_provenance():
    legacy = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "properties": [
                    {
                        "name": "org.qrypton.evidence",
                        "value": json.dumps(
                            {
                                "id": "evidence_1",
                                "excerpt": "PRIVATE KEY RAW SECRET",
                                "attributes": {"token": "SECRET-ATTRIBUTE"},
                                "provenance": {"scanner_name": "source-ast"},
                            }
                        ),
                    },
                    {
                        "name": "org.qrypton.finding.canonical",
                        "value": json.dumps(
                            {
                                "algorithm": {
                                    "state": "unknown",
                                    "value": {
                                        "parameters": {"private_key": "SECRET-PARAMETER"},
                                    },
                                },
                            }
                        ),
                    },
                    {
                        "name": "org.qrypton.algorithm.parameters",
                        "value": json.dumps(
                            {
                                "private_key": "SECRET-PARAMETER",
                            }
                        ),
                    },
                ]
            }
        ],
    }
    original = json.dumps(legacy).encode()
    exported = sanitize_persisted_cbom(original)
    assert b"SECRET" not in exported
    assert b"source-ast" in exported
    assert b'"state": "unknown"' in exported or b'\\"state\\":\\"unknown\\"' in exported
    assert original != exported
