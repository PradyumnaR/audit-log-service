"""Integration tests for GET /audit/events against a real SQLite file."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.domain.hashing import GENESIS_HASH
from audit_log.schema.events import REDACTED
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import NewEvent, append_event


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    # A file database: TestClient runs sync endpoints in worker threads, and in-memory
    # SQLite would give each thread its own separate database.
    monkeypatch.delenv("SENSITIVE_FIELDS", raising=False)
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    create_schema(engine)
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
        "payload": {"field": "mailingAddress", "newValue": "48 Pine Ave"},
    }
    body.update(overrides)
    return body


def _clock(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


def _seed_at(engine: Engine, *moments: datetime, **overrides: Any) -> None:
    """Append events with fixed server timestamps (POST always uses the current time)."""
    values: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"field": "mailingAddress"},
    }
    values.update(overrides)
    with Session(engine) as session:
        for moment in moments:
            append_event(session, NewEvent(**values), sensitive_fields=(), now=_clock(moment))


def _ids(response: Any) -> list[int]:
    assert response.status_code == 200
    return [item["id"] for item in response.json()["items"]]


def test_returns_posted_event_with_hashes(client: TestClient) -> None:
    posted = client.post("/audit/events", json=_body()).json()

    response = client.get("/audit/events")

    assert response.status_code == 200
    data = response.json()
    assert data["nextCursor"] is None
    [item] = data["items"]
    assert set(item) == {*posted, "contentHash", "previousHash"}
    assert {key: item[key] for key in posted} == posted
    assert item["previousHash"] == GENESIS_HASH
    assert len(item["contentHash"]) == 64
    assert "fieldSalts" not in item
    assert "archived" not in item


def test_empty_log(client: TestClient) -> None:
    assert client.get("/audit/events").json() == {"items": [], "nextCursor": None}


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        pytest.param({"actorId": "user-2001"}, [2], id="actor"),
        pytest.param({"eventType": "USER_LOGIN"}, [3], id="event-type"),
        pytest.param({"resourceType": "USER"}, [3], id="resource-type"),
        pytest.param({"resourceType": "ACCOUNT", "resourceId": "acct-2"}, [2], id="resource"),
        pytest.param({"resourceType": "ACCOUNT", "actorId": "user-1042"}, [1, 4], id="combined"),
        pytest.param({"actorId": "nobody"}, [], id="no-match"),
    ],
)
def test_filters(client: TestClient, params: dict[str, str], expected: list[int]) -> None:
    client.post("/audit/events", json=_body())
    client.post("/audit/events", json=_body(actorId="user-2001", resourceId="acct-2"))
    client.post(
        "/audit/events",
        json=_body(eventType="USER_LOGIN", actorId="user-3001", resourceType="USER"),
    )
    client.post("/audit/events", json=_body())

    assert _ids(client.get("/audit/events", params=params)) == expected


def test_time_range_from_inclusive_to_exclusive(client: TestClient, engine: Engine) -> None:
    _seed_at(engine, *(datetime(2026, 9, 24, hour, tzinfo=UTC) for hour in (9, 10, 11, 12)))

    params = {"from": "2026-09-24T10:00:00Z", "to": "2026-09-24T12:00:00Z"}
    assert _ids(client.get("/audit/events", params=params)) == [2, 3]
    assert _ids(client.get("/audit/events", params={"from": "2026-09-24T11:00:00Z"})) == [3, 4]
    assert _ids(client.get("/audit/events", params={"to": "2026-09-24T10:00:00Z"})) == [1]
    # Offsets are converted to UTC: 12:00+02:00 is 10:00Z.
    assert _ids(client.get("/audit/events", params={"to": "2026-09-24T12:00:00+02:00"})) == [1]


def test_time_range_combines_with_filters(client: TestClient, engine: Engine) -> None:
    _seed_at(engine, datetime(2026, 9, 24, 10, tzinfo=UTC))
    _seed_at(engine, datetime(2026, 9, 24, 11, tzinfo=UTC), actor_id="user-2001")
    _seed_at(engine, datetime(2026, 9, 24, 12, tzinfo=UTC))

    params = {"actorId": "user-1042", "from": "2026-09-24T10:30:00Z"}
    assert _ids(client.get("/audit/events", params=params)) == [3]


def test_cursor_pagination_walks_all_records(client: TestClient) -> None:
    for i in range(5):
        client.post("/audit/events", json=_body(actorId=f"user-{i}"))

    seen: list[int] = []
    cursors: list[str | None] = []
    params: dict[str, Any] = {"limit": 2}
    while True:
        data = client.get("/audit/events", params=params).json()
        seen += [item["id"] for item in data["items"]]
        cursors.append(data["nextCursor"])
        if data["nextCursor"] is None:
            break
        params["cursor"] = data["nextCursor"]

    assert seen == [1, 2, 3, 4, 5]
    assert cursors == ["2", "4", None]


def test_pagination_respects_filters(client: TestClient) -> None:
    for actor in ["a-1", "b-1", "a-1", "b-1", "a-1"]:
        client.post("/audit/events", json=_body(actorId=actor))

    first = client.get("/audit/events", params={"actorId": "a-1", "limit": 2}).json()
    assert [item["id"] for item in first["items"]] == [1, 3]
    params = {"actorId": "a-1", "limit": 2, "cursor": first["nextCursor"]}
    second = client.get("/audit/events", params=params).json()
    assert [item["id"] for item in second["items"]] == [5]
    assert second["nextCursor"] is None


def test_default_limit(client: TestClient, engine: Engine) -> None:
    _seed_at(engine, *[datetime(2026, 9, 24, tzinfo=UTC)] * 51)

    data = client.get("/audit/events").json()

    assert len(data["items"]) == 50
    assert data["nextCursor"] == "50"


def test_archived_records_are_not_returned(client: TestClient, engine: Engine) -> None:
    for _ in range(3):
        client.post("/audit/events", json=_body())
    with Session(engine) as session:
        session.execute(
            text(
                "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
                " resource_type = NULL, resource_id = NULL, payload = NULL WHERE id = 1"
            )
        )
        session.commit()

    assert _ids(client.get("/audit/events")) == [2, 3]


def test_sensitive_values_shown_until_redacted(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    payload = {"accountNumber": "0000-TEST", "field": "mailingAddress"}
    client.post("/audit/events", json=_body(payload=payload))
    assert client.get("/audit/events").json()["items"][0]["payload"] == payload

    # What redaction leaves behind (scenario B): value and salt gone, field hash kept.
    with Session(engine) as session:
        session.execute(
            text(
                "UPDATE audit_events SET payload = json_remove(payload, '$.accountNumber'),"
                " field_salts = '{}' WHERE id = 1"
            )
        )
        session.commit()

    item = client.get("/audit/events").json()["items"][0]
    assert item["payload"] == {"accountNumber": REDACTED, "field": "mailingAddress"}
    assert "0000-TEST" not in client.get("/audit/events").text


@pytest.mark.parametrize(
    ("params", "loc"),
    [
        pytest.param({"resourceId": "acct-88731"}, ["query"], id="id-without-type"),
        pytest.param({"eventType": "user_login"}, ["query", "eventType"], id="bad-event-type"),
        pytest.param({"resourceType": "Account"}, ["query", "resourceType"], id="bad-type"),
        pytest.param({"actorId": " user-1"}, ["query", "actorId"], id="bad-actor"),
        pytest.param({"actorID": "user-1042"}, ["query", "actorID"], id="unknown-param"),
        pytest.param({"from": "2026-09-24T10:00:00"}, ["query", "from"], id="naive-from"),
        pytest.param({"to": "1727172000"}, ["query", "to"], id="epoch-to"),
        pytest.param(
            {"from": "2026-09-24T10:00:00Z", "to": "2026-09-24T09:00:00Z"},
            ["query"],
            id="from-after-to",
        ),
        pytest.param({"limit": "0"}, ["query", "limit"], id="limit-zero"),
        pytest.param({"limit": "201"}, ["query", "limit"], id="limit-too-large"),
        pytest.param({"cursor": "abc"}, ["query", "cursor"], id="bad-cursor"),
    ],
)
def test_bad_query_is_rejected(client: TestClient, params: dict[str, str], loc: list[str]) -> None:
    response = client.get("/audit/events", params=params)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert [error["loc"] for error in errors] == [loc]
    assert all("input" not in error for error in errors)


def test_cursor_past_end_returns_empty_page(client: TestClient) -> None:
    client.post("/audit/events", json=_body())
    assert client.get("/audit/events", params={"cursor": "99"}).json() == {
        "items": [],
        "nextCursor": None,
    }
