"""Integration tests for GET /audit/export and offline verification of the bundle."""

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.domain.hashing import compute_bundle_hash
from audit_log.schema.events import REDACTED
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import archive_before, redact_field

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_bundle.py"


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as client:
        yield client


def _post(client: TestClient, **overrides: Any) -> None:
    body: dict[str, Any] = {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-1042",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-88731",
        "payload": {"accountNumber": "0000-TEST", "field": "mailingAddress"},
    }
    body.update(overrides)
    assert client.post("/audit/events", json=body).status_code == 201


def _export(client: TestClient, **params: str) -> dict[str, Any]:
    response = client.get("/audit/export", params=params)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def _verify_offline(tmp_path: Path, bundle: Any) -> subprocess.CompletedProcess[str]:
    """Run a copy of the script alone, isolated from the project and site-packages."""
    workdir = tmp_path / "recipient"
    workdir.mkdir(exist_ok=True)
    script = workdir / "verify_bundle.py"
    shutil.copy(SCRIPT, script)
    (workdir / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - fixed argv (this repo's script), no shell
        [sys.executable, "-I", "-S", str(script), "bundle.json"],
        cwd=workdir,
        env={},
        capture_output=True,
        text=True,
        check=False,
    )


def test_export_by_actor(client: TestClient) -> None:
    _post(client)
    _post(client, actorId="user-2001")
    _post(client, resourceId="acct-00001")

    data = _export(client, actorId="user-1042")

    assert [record["id"] for record in data["records"]] == [1, 3]
    metadata = data["metadata"]
    assert metadata["filter"] == {"actorId": "user-1042"}
    assert metadata["hashAlgorithm"] == "SHA-256"
    assert metadata["serialization"] == "canonical JSON (sorted keys, no whitespace)"
    assert metadata["sensitiveFields"] == ["accountNumber"]
    assert metadata["recordCount"] == 2
    assert datetime.fromisoformat(metadata["exportedAt"]) <= datetime.now(UTC)
    assert data["bundleHash"] == compute_bundle_hash(r["contentHash"] for r in data["records"])
    record = data["records"][0]
    assert set(record) == {
        "id",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "payload",
        "timestamp",
        "fieldHashes",
        "fieldSalts",
        "previousHash",
        "contentHash",
    }
    assert set(record["fieldHashes"]) == set(record["fieldSalts"]) == {"accountNumber"}


def test_export_by_resource(client: TestClient) -> None:
    _post(client)
    _post(client, resourceId="acct-00001")
    _post(client, resourceType="CARD")

    data = _export(client, resourceType="ACCOUNT", resourceId="acct-88731")

    assert [record["id"] for record in data["records"]] == [1]
    assert data["metadata"]["filter"] == {"resourceType": "ACCOUNT", "resourceId": "acct-88731"}


def test_no_matches_gives_empty_bundle(client: TestClient, tmp_path: Path) -> None:
    data = _export(client, actorId="nobody")
    assert data["records"] == []
    assert data["metadata"]["recordCount"] == 0
    assert _verify_offline(tmp_path, data).returncode == 0


def test_archived_excluded_and_redacted_included(
    client: TestClient, engine: Engine, tmp_path: Path
) -> None:
    for _ in range(3):
        _post(client)
    with Session(engine) as session:
        archive_before(session, (datetime.now(UTC) + timedelta(seconds=1)).replace(microsecond=0))
    _post(client)
    _post(client)
    with Session(engine) as session:
        redact_field(session, 5, "accountNumber")

    data = _export(client, actorId="user-1042")

    assert [record["id"] for record in data["records"]] == [4, 5]
    redacted = data["records"][1]
    assert redacted["payload"] == {"accountNumber": REDACTED, "field": "mailingAddress"}
    assert redacted["fieldSalts"] == {}
    assert "accountNumber" in redacted["fieldHashes"]
    assert _verify_offline(tmp_path, data).returncode == 0


@pytest.mark.parametrize(
    ("params", "message"),
    [
        pytest.param({}, "requires actorId", id="none"),
        pytest.param({"resourceId": "acct-88731"}, "resourceId requires resourceType", id="id"),
        pytest.param({"resourceType": "ACCOUNT"}, "requires resourceId", id="type-only"),
        pytest.param(
            {"actorId": "user-1042", "resourceType": "ACCOUNT", "resourceId": "acct-88731"},
            "not both",
            id="both",
        ),
        pytest.param({"actorId": "user-1042", "limit": "5"}, "Extra", id="unknown-param"),
    ],
)
def test_invalid_query_is_422(client: TestClient, params: dict[str, str], message: str) -> None:
    response = client.get("/audit/export", params=params)
    assert response.status_code == 422
    assert message in response.text


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_export_is_read_only(client: TestClient, method: str) -> None:
    assert client.request(method, "/audit/export").status_code == 405


def test_offline_verifier_passes_untouched_and_fails_altered(
    client: TestClient, tmp_path: Path
) -> None:
    for _ in range(3):
        _post(client)
    bundle = _export(client, actorId="user-1042")

    intact = _verify_offline(tmp_path, bundle)
    assert intact.returncode == 0, intact.stderr
    assert "intact (3 record(s))" in intact.stdout

    edited = json.loads(json.dumps(bundle))
    edited["records"][1]["payload"]["field"] = "edited"
    result = _verify_offline(tmp_path, edited)
    assert result.returncode == 1
    assert "record 2: contentHash does not match" in result.stderr

    removed = json.loads(json.dumps(bundle))
    del removed["records"][1]
    removed["metadata"]["recordCount"] = 2
    result = _verify_offline(tmp_path, removed)
    assert result.returncode == 1
    assert "bundleHash does not match" in result.stderr
