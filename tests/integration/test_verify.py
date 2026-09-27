"""Integration tests for GET /audit/verify against a real SQLite file."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.storage.database import make_engine


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    # A file database: TestClient runs sync endpoints in worker threads, and in-memory
    # SQLite would give each thread its own separate database.
    monkeypatch.delenv("SENSITIVE_FIELDS", raising=False)
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as client:
        yield client


def _post(client: TestClient, count: int, **overrides: Any) -> None:
    for i in range(count):
        body: dict[str, Any] = {
            "eventType": "RECORD_UPDATED",
            "actorId": f"user-{i}",
            "resourceType": "ACCOUNT",
            "resourceId": "acct-88731",
            "payload": {"field": "mailingAddress", "newValue": "48 Pine Ave"},
        }
        body.update(overrides)
        assert client.post("/audit/events", json=body).status_code == 201


def _sql(engine: Engine, statement: str, **params: Any) -> None:
    """Tamper with the database directly, bypassing the API."""
    with Session(engine) as session:
        session.execute(text(statement), params)
        session.commit()


def _archive(engine: Engine, record_id: int) -> None:
    _sql(
        engine,
        "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
        " resource_type = NULL, resource_id = NULL, payload = NULL WHERE id = :id",
        id=record_id,
    )


def _verify(client: TestClient) -> dict[str, Any]:
    response = client.get("/audit/verify")
    assert response.status_code == 200
    data: dict[str, Any] = response.json()
    return data


def test_empty_log_is_intact(client: TestClient) -> None:
    assert _verify(client) == {"intact": True, "recordsChecked": 0}


def test_intact_chain(client: TestClient) -> None:
    _post(client, 5)
    assert _verify(client) == {"intact": True, "recordsChecked": 5}


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("UPDATE audit_events SET actor_id = 'user-9999' WHERE id = 3", id="actor"),
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.newValue', 'x') WHERE id = 3",
            id="payload",
        ),
        pytest.param(
            "UPDATE audit_events SET timestamp = '2020-01-01T00:00:00Z' WHERE id = 3",
            id="timestamp",
        ),
        pytest.param(
            "UPDATE audit_events SET content_hash = printf('%064d', 0) WHERE id = 3",
            id="content-hash",
        ),
    ],
)
def test_direct_edit_is_content_hash_mismatch(
    client: TestClient, engine: Engine, statement: str
) -> None:
    _post(client, 5)
    _sql(engine, statement)

    assert _verify(client) == {
        "intact": False,
        "recordsChecked": 3,
        "firstBrokenRecordId": 3,
        "violationType": "CONTENT_HASH_MISMATCH",
        "detail": "Stored contentHash does not match recomputed hash",
    }


def test_deleted_record_is_broken_link(client: TestClient, engine: Engine) -> None:
    _post(client, 5)
    _sql(engine, "DELETE FROM audit_events WHERE id = 2")

    data = _verify(client)

    assert data == {
        "intact": False,
        "recordsChecked": 2,
        "firstBrokenRecordId": 3,
        "violationType": "BROKEN_LINK",
        "detail": "previousHash does not match the preceding record's contentHash",
    }


def test_edited_previous_hash_is_broken_link(client: TestClient, engine: Engine) -> None:
    _post(client, 3)
    _sql(engine, "UPDATE audit_events SET previous_hash = printf('%064d', 0) WHERE id = 1")

    data = _verify(client)

    assert data["firstBrokenRecordId"] == 1
    assert data["violationType"] == "BROKEN_LINK"
    assert "genesis" in data["detail"]


def test_archived_prefix_is_intact(client: TestClient, engine: Engine) -> None:
    _post(client, 4)
    _archive(engine, 1)
    _archive(engine, 2)
    assert _verify(client) == {"intact": True, "recordsChecked": 4}


def test_archive_gap_is_invalid_archive(client: TestClient, engine: Engine) -> None:
    _post(client, 4)
    _archive(engine, 3)

    data = _verify(client)

    assert data["intact"] is False
    assert data["firstBrokenRecordId"] == 3
    assert data["violationType"] == "INVALID_ARCHIVE"


def test_edited_sensitive_value_is_detected(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    _post(client, 3, payload={"accountNumber": "0000-TEST"})
    _sql(
        engine,
        "UPDATE audit_events SET payload = json_set(payload, '$.accountNumber', '1111-TEST')"
        " WHERE id = 2",
    )

    data = _verify(client)

    assert data["firstBrokenRecordId"] == 2
    assert data["violationType"] == "CONTENT_HASH_MISMATCH"
    assert "accountNumber" in data["detail"]
    assert "0000-TEST" not in str(data)
    assert "1111-TEST" not in str(data)


def test_redacted_sensitive_value_is_intact(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    _post(client, 3, payload={"accountNumber": "0000-TEST"})
    # What redaction leaves behind (scenario B): value and salt gone, field hash kept.
    _sql(
        engine,
        "UPDATE audit_events SET payload = json_remove(payload, '$.accountNumber'),"
        " field_salts = '{}' WHERE id = 2",
    )
    assert _verify(client) == {"intact": True, "recordsChecked": 3}


def test_verify_does_not_change_records(client: TestClient) -> None:
    _post(client, 2)
    before = client.get("/audit/events").json()
    _verify(client)
    assert client.get("/audit/events").json() == before


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_verify_is_read_only(client: TestClient, method: str) -> None:
    assert client.request(method, "/audit/verify").status_code == 405


def test_openapi_exposes_only_get_on_verify(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/audit/verify"]) == {"get"}
