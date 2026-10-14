"""The synthetic Network Inspection preview has no backend scan API."""

from fastapi.testclient import TestClient

from qrypton.api.app import app


def test_network_inspection_api_refuses_without_sample_mode() -> None:
    response = TestClient(app).get("/api/v1/network-inspection")
    assert response.status_code == 404
