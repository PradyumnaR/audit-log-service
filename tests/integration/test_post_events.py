"""Integration tests for POST /audit/events against a real SQLite file."""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.domain.hashing import GENESIS_HASH, compute_content_hash, compute_field_hash
from audit_log.schema.events import MAX_PAYLOAD_BYTES
from audit_log.storage.database import make_engine
from audit_log.storage.models import AuditEvent

TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


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


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-1042",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-88731",
        "payload": {
            "field": "mailingAddress",
            "oldValue": "12 Oak St",
            "newValue": "48 Pine Ave",
        },
    }
    body.update(overrides)
    return body


def _count(engine: Engine) -> int:
    with Session(engine) as session:
        return session.scalar(select(func.count()).select_from(AuditEvent)) or 0


def test_valid_event_is_saved_and_returned(client: TestClient, engine: Engine) -> None:
    response = client.post("/audit/events", json=_body())

    assert response.status_code == 201
    data = response.json()
    assert set(data) == {
        "id",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "payload",
        "timestamp",
    }
    assert data["id"] == 1
    assert {key: data[key] for key in _body()} == _body()
    assert TIMESTAMP_PATTERN.match(data["timestamp"])

    with Session(engine) as session:
        record = session.get_one(AuditEvent, 1)
        assert record.event_type == "RECORD_UPDATED"
        assert record.actor_id == "user-1042"
        assert record.resource_type == "ACCOUNT"
        assert record.resource_id == "acct-88731"
        assert record.payload == _body()["payload"]
        assert record.timestamp == data["timestamp"]
        assert record.previous_hash == GENESIS_HASH
        assert record.archived is False


def test_posted_events_form_a_chain(client: TestClient, engine: Engine) -> None:
    ids = [
        client.post("/audit/events", json=_body(actorId=f"user-{i}")).json()["id"] for i in range(3)
    ]
    assert ids == [1, 2, 3]

    with Session(engine) as session:
        records = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    previous_hash = GENESIS_HASH
    for record in records:
        assert record.previous_hash == previous_hash
        assert record.event_type is not None
        assert record.actor_id is not None
        assert record.resource_type is not None
        assert record.resource_id is not None
        assert record.payload is not None
        assert record.content_hash == compute_content_hash(
            event_type=record.event_type,
            actor_id=record.actor_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            timestamp=record.timestamp,
            payload=record.payload,
            field_hashes=record.field_hashes,
            previous_hash=record.previous_hash,
        )
        previous_hash = record.content_hash


def test_sensitive_fields_are_salted_and_hashed(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    payload = {"accountNumber": "0000-TEST", "field": "mailingAddress"}

    response = client.post("/audit/events", json=_body(payload=payload))

    assert response.status_code == 201
    assert response.json()["payload"] == payload
    with Session(engine) as session:
        record = session.get_one(AuditEvent, 1)
        salt = record.field_salts["accountNumber"]
        assert record.field_hashes == {"accountNumber": compute_field_hash(salt, "0000-TEST")}


def test_caller_timestamp_is_rejected(client: TestClient, engine: Engine) -> None:
    response = client.post("/audit/events", json=_body(timestamp="2020-01-01T00:00:00Z"))
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "timestamp"]
    assert _count(engine) == 0


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({k: v for k, v in _body().items() if k != "actorId"}, id="missing-field"),
        pytest.param(_body(eventType="user_login"), id="bad-event-type"),
        pytest.param(_body(resourceType="Account"), id="bad-resource-type"),
        pytest.param(_body(actorId=""), id="empty-actor"),
        pytest.param(_body(resourceId=12), id="wrong-type"),
        pytest.param(_body(payload="text"), id="payload-not-object"),
        pytest.param(_body(unexpected=True), id="unknown-field"),
        pytest.param(_body(id=99), id="client-id"),
        pytest.param(_body(payload={"k": "x" * MAX_PAYLOAD_BYTES}), id="oversized-payload"),
    ],
)
def test_bad_input_is_rejected_and_not_saved(
    client: TestClient, engine: Engine, body: dict[str, Any]
) -> None:
    response = client.post("/audit/events", json=body)
    assert response.status_code == 422
    assert _count(engine) == 0


def test_non_finite_number_in_payload_is_rejected(client: TestClient, engine: Engine) -> None:
    # Python's JSON parser accepts NaN; it cannot be canonically serialized for hashing.
    raw = json.dumps(_body(payload={"amount": float("nan")}))
    response = client.post(
        "/audit/events", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert _count(engine) == 0


@pytest.mark.parametrize("content", ["not json", "[1, 2]", ""])
def test_malformed_json_is_rejected(client: TestClient, engine: Engine, content: str) -> None:
    response = client.post(
        "/audit/events", content=content, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert _count(engine) == 0


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(("path", "expected"), [("/audit/events", 405), ("/audit/events/1", 404)])
def test_no_update_or_delete(
    client: TestClient, engine: Engine, method: str, path: str, expected: int
) -> None:
    client.post("/audit/events", json=_body())

    response = client.request(method, path, json=_body())

    assert response.status_code == expected
    with Session(engine) as session:
        record = session.get_one(AuditEvent, 1)
        assert record.actor_id == "user-1042"
    assert _count(engine) == 1


def test_openapi_exposes_only_post_on_events(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/audit/events"]) == {"post"}
    assert not [path for path in paths if path.startswith("/audit/events/")]


def test_validation_errors_do_not_echo_input(client: TestClient) -> None:
    response = client.post("/audit/events", json=_body(actorId="", payload="0000-TEST"))
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert {tuple(error["loc"]) for error in errors} == {("body", "actorId"), ("body", "payload")}
    assert all("input" not in error for error in errors)
    assert "0000-TEST" not in response.text
