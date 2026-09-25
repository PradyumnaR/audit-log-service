"""Smoke tests confirming the FastAPI app boots."""

from fastapi.testclient import TestClient

from audit_log.api.app import create_app


def test_openapi_schema_served() -> None:
    client = TestClient(create_app())
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Audit Log Service"
