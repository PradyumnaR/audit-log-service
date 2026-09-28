"""Integration tests for GET /audit/reports/account-access against a real SQLite file."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.schema.events import REDACTED
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import NewEvent, append_event, archive_before, redact_field

URL = "/audit/reports/account-access"
DAY = {"from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z"}


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    # A file database: TestClient runs sync endpoints in worker threads.
    monkeypatch.delenv("SENSITIVE_FIELDS", raising=False)
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as client:
        yield client


def _seed(engine: Engine, hour: int, *, sensitive: tuple[str, ...] = (), **overrides: Any) -> None:
    """Append one event at 2026-09-24 ``hour``:00Z (POST always uses the current time)."""
    values: dict[str, Any] = {
        "event_type": "ACCOUNT_VIEWED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"channel": "web"},
    }
    values.update(overrides)
    moment = datetime(2026, 9, 24, hour, tzinfo=UTC)
    with Session(engine) as session:
        append_event(session, NewEvent(**values), sensitive_fields=sensitive, now=lambda: moment)


def _ids(response: Any) -> list[int]:
    assert response.status_code == 200
    return [item["id"] for item in response.json()["items"]]


def test_returns_only_account_access_events(client: TestClient, engine: Engine) -> None:
    _seed(engine, 1)  # 1
    _seed(engine, 2, event_type="ACCOUNT_UPDATED")  # 2
    _seed(engine, 3, event_type="ACCOUNT_EXPORTED")  # 3
    _seed(engine, 4, event_type="RECORD_UPDATED")  # 4: not an access event type
    _seed(engine, 5, resource_type="USER")  # 5: not account data
    _seed(engine, 6, event_type="USER_LOGIN", resource_type="USER")  # 6

    response = client.get(URL, params=DAY)

    assert _ids(response) == [1, 2, 3]
    assert response.json()["nextCursor"] is None


def test_response_matches_get_events_format(client: TestClient, engine: Engine) -> None:
    _seed(engine, 1)

    report = client.get(URL, params=DAY).json()
    events = client.get("/audit/events", params=DAY).json()

    assert report == events
    [item] = report["items"]
    assert item["eventType"] == "ACCOUNT_VIEWED"
    assert item["timestamp"] == "2026-09-24T01:00:00Z"
    assert {"contentHash", "previousHash"} <= set(item)


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        pytest.param({}, [1, 2, 3, 4], id="range-only"),
        pytest.param({"resourceId": "acct-2"}, [2, 4], id="resource"),
        pytest.param({"actorId": "user-2001"}, [3, 4], id="actor"),
        pytest.param({"resourceId": "acct-2", "actorId": "user-2001"}, [4], id="both"),
        pytest.param({"actorId": "nobody"}, [], id="no-match"),
    ],
)
def test_optional_filters(
    client: TestClient, engine: Engine, params: dict[str, str], expected: list[int]
) -> None:
    _seed(engine, 1)
    _seed(engine, 2, resource_id="acct-2")
    _seed(engine, 3, actor_id="user-2001")
    _seed(engine, 4, actor_id="user-2001", resource_id="acct-2")
    # Same account id under another resource type is not account data.
    _seed(engine, 5, actor_id="user-2001", resource_type="USER", resource_id="acct-2")

    assert _ids(client.get(URL, params={**DAY, **params})) == expected


def test_time_range_from_inclusive_to_exclusive(client: TestClient, engine: Engine) -> None:
    for hour in (9, 10, 11, 12):
        _seed(engine, hour)

    params = {"from": "2026-09-24T10:00:00Z", "to": "2026-09-24T12:00:00Z"}
    assert _ids(client.get(URL, params=params)) == [2, 3]
    # Offsets are converted to UTC: 12:00+02:00 is 10:00Z.
    params = {"from": "2026-09-24T00:00:00Z", "to": "2026-09-24T12:00:00+02:00"}
    assert _ids(client.get(URL, params=params)) == [1]


def test_cursor_pagination_walks_all_access_events(client: TestClient, engine: Engine) -> None:
    for hour in range(1, 8):
        # Interleave non-access events so pages must skip them.
        _seed(engine, hour, event_type="ACCOUNT_VIEWED" if hour % 2 else "RECORD_UPDATED")

    seen: list[int] = []
    cursors: list[str | None] = []
    params: dict[str, Any] = {**DAY, "limit": 2}
    while True:
        data = client.get(URL, params=params).json()
        seen += [item["id"] for item in data["items"]]
        cursors.append(data["nextCursor"])
        if data["nextCursor"] is None:
            break
        params["cursor"] = data["nextCursor"]

    assert seen == [1, 3, 5, 7]
    assert cursors == ["3", None]


def test_archived_events_are_excluded(client: TestClient, engine: Engine) -> None:
    for hour in (1, 2, 3):
        _seed(engine, hour)
    with Session(engine) as session:
        archive_before(session, datetime(2026, 9, 24, 2, tzinfo=UTC))

    assert _ids(client.get(URL, params=DAY)) == [2, 3]


def test_redacted_values_are_masked(client: TestClient, engine: Engine) -> None:
    _seed(engine, 1, sensitive=("accountNumber",), payload={"accountNumber": "0000-TEST"})
    with Session(engine) as session:
        redact_field(session, 1, "accountNumber", sensitive_fields=("accountNumber",))

    response = client.get(URL, params=DAY)

    assert response.json()["items"][0]["payload"] == {"accountNumber": REDACTED}
    assert "0000-TEST" not in response.text


@pytest.mark.parametrize(
    ("params", "loc"),
    [
        pytest.param({"to": DAY["to"]}, ["query", "from"], id="missing-from"),
        pytest.param({"from": DAY["from"]}, ["query", "to"], id="missing-to"),
        pytest.param({**DAY, "from": "2026-09-24T10:00:00"}, ["query", "from"], id="naive-from"),
        pytest.param({**DAY, "to": "1727172000"}, ["query", "to"], id="epoch-to"),
        pytest.param({**DAY, "from": DAY["to"], "to": DAY["from"]}, ["query"], id="from-after-to"),
        pytest.param({**DAY, "resourceType": "USER"}, ["query", "resourceType"], id="type"),
        pytest.param({**DAY, "eventType": "USER_LOGIN"}, ["query", "eventType"], id="event-type"),
        pytest.param({**DAY, "actorId": " user-1"}, ["query", "actorId"], id="bad-actor"),
        pytest.param({**DAY, "limit": "0"}, ["query", "limit"], id="limit-zero"),
        pytest.param({**DAY, "cursor": "abc"}, ["query", "cursor"], id="bad-cursor"),
    ],
)
def test_bad_query_is_rejected(client: TestClient, params: dict[str, str], loc: list[str]) -> None:
    response = client.get(URL, params=params)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert [error["loc"] for error in errors] == [loc]
    assert all("input" not in error for error in errors)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_report_is_read_only(client: TestClient, method: str) -> None:
    assert client.request(method, URL, params=DAY).status_code == 405
