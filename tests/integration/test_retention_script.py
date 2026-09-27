"""Integration tests for the retention script against a real SQLite file."""

import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.api.app import create_app
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import NewEvent, append_event

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_retention.py"


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'audit.db'}"


@pytest.fixture
def engine(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.delenv("SENSITIVE_FIELDS", raising=False)
    engine = make_engine(db_url)
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as client:
        yield client


def _clock(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


def _seed(engine: Engine, ages_in_days: list[int]) -> None:
    """Append records with past timestamps (the API always stamps the current time)."""
    now = datetime.now(UTC)
    with Session(engine) as session:
        for i, age in enumerate(ages_in_days):
            append_event(
                session,
                NewEvent(
                    event_type="RECORD_UPDATED",
                    actor_id=f"user-{i}",
                    resource_type="ACCOUNT",
                    resource_id="acct-88731",
                    payload={"accountNumber": "0000-TEST", "field": "mailingAddress"},
                ),
                sensitive_fields=("accountNumber",),
                now=_clock(now - timedelta(days=age)),
            )


def _run_script(db_url: str, **env: str) -> subprocess.CompletedProcess[str]:
    child_env = {k: v for k, v in os.environ.items() if k != "RETENTION_DAYS"}
    child_env.update(DATABASE_URL=db_url, **env)
    return subprocess.run(  # noqa: S603 - fixed argv (this repo's script), no shell
        [sys.executable, str(SCRIPT)],
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )


def _json(client: TestClient, path: str) -> dict[str, Any]:
    response = client.get(path)
    assert response.status_code == 200
    data: dict[str, Any] = response.json()
    return data


def test_script_archives_old_records_and_verify_passes(
    client: TestClient, engine: Engine, db_url: str
) -> None:
    _seed(engine, [90, 45, 31, 10, 0])

    result = _run_script(db_url, RETENTION_DAYS="30")

    assert result.returncode == 0, result.stderr
    assert "archived 3 record(s)" in result.stdout
    assert _json(client, "/audit/verify") == {"intact": True, "recordsChecked": 5}
    items = _json(client, "/audit/events")["items"]
    assert [item["actorId"] for item in items] == ["user-3", "user-4"]


def test_new_events_after_retention_keep_chain_intact(
    client: TestClient, engine: Engine, db_url: str
) -> None:
    _seed(engine, [90, 45])
    assert _run_script(db_url, RETENTION_DAYS="30").returncode == 0

    body = {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-2001",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-88731",
        "payload": {"field": "mailingAddress"},
    }
    assert client.post("/audit/events", json=body).status_code == 201

    assert _json(client, "/audit/verify") == {"intact": True, "recordsChecked": 3}


def test_archive_out_of_order_after_retention_is_invalid_archive(
    client: TestClient, engine: Engine, db_url: str
) -> None:
    _seed(engine, [90, 45, 10, 0])
    assert _run_script(db_url, RETENTION_DAYS="30").returncode == 0
    with Session(engine) as session:
        session.connection().exec_driver_sql("UPDATE audit_events SET archived = 1 WHERE id = 4")
        session.commit()

    data = _json(client, "/audit/verify")

    assert data["intact"] is False
    assert data["firstBrokenRecordId"] == 4
    assert data["violationType"] == "INVALID_ARCHIVE"


def test_script_without_retention_days_fails_and_changes_nothing(
    client: TestClient, engine: Engine, db_url: str
) -> None:
    _seed(engine, [90])

    result = _run_script(db_url)

    assert result.returncode == 1
    assert "RETENTION_DAYS is not set" in result.stderr
    assert len(_json(client, "/audit/events")["items"]) == 1
