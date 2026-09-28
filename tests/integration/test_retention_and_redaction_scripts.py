"""End-to-end test: retention and redaction scripts together, then verify and export (B5)."""

import json
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
from audit_log.domain.hashing import format_timestamp
from audit_log.schema.events import REDACTED
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import NewEvent, append_event

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'audit.db'}"


@pytest.fixture
def engine(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    engine = make_engine(db_url)
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine: Engine, db_url: str) -> Iterator[TestClient]:
    """Five records (ages 90, 45, 10, 5, 0 days): ids 1-2 archived, id 4 redacted."""
    now = datetime.now(UTC)
    with Session(engine) as session:
        for age in (90, 45, 10, 5, 0):
            append_event(
                session,
                NewEvent(
                    event_type="RECORD_UPDATED",
                    actor_id="user-1042",
                    resource_type="ACCOUNT",
                    resource_id="acct-88731",
                    payload={"accountNumber": "0000-TEST", "field": "mailingAddress"},
                ),
                now=_clock(now - timedelta(days=age)),
            )
    before = format_timestamp(now - timedelta(days=30))
    assert _run(db_url, "run_retention.py", "--before", before).returncode == 0
    assert _run(db_url, "redact.py", "--id", "4", "--field", "accountNumber").returncode == 0
    with TestClient(create_app(engine)) as client:
        yield client


def _clock(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


def _run(db_url: str, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    child_env = {**os.environ, "DATABASE_URL": db_url}
    return subprocess.run(  # noqa: S603 - fixed argv (this repo's scripts), no shell
        [sys.executable, str(SCRIPTS / script), *args],
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )


def _json(client: TestClient, path: str) -> dict[str, Any]:
    response = client.get(path)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def _verify_bundle(tmp_path: Path, bundle: Any) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - fixed argv (this repo's script), no shell
        [sys.executable, "-I", "-S", str(SCRIPTS / "verify_bundle.py"), str(path)],
        env={},
        capture_output=True,
        text=True,
        check=False,
    )


def test_chain_verifies_and_reads_show_both(client: TestClient) -> None:
    assert _json(client, "/audit/verify") == {"intact": True, "recordsChecked": 5}
    items = _json(client, "/audit/events")["items"]
    assert [item["id"] for item in items] == [3, 4, 5]
    assert items[1]["payload"]["accountNumber"] == REDACTED
    assert items[0]["payload"]["accountNumber"] == "0000-TEST"


def test_export_excludes_archived_and_verifies_offline(client: TestClient, tmp_path: Path) -> None:
    bundle = _json(client, "/audit/export?actorId=user-1042")
    assert [record["id"] for record in bundle["records"]] == [3, 4, 5]

    result = _verify_bundle(tmp_path, bundle)

    assert result.returncode == 0, result.stderr


def test_redacting_an_archived_record_is_refused(client: TestClient, db_url: str) -> None:
    result = _run(db_url, "redact.py", "--id", "1", "--field", "accountNumber")
    assert result.returncode == 1
    assert "archived" in result.stderr
    assert _json(client, "/audit/verify")["intact"] is True


@pytest.mark.parametrize(
    ("statement", "record_id", "violation"),
    [
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.field', 'x') WHERE id = 4",
            4,
            "CONTENT_HASH_MISMATCH",
            id="edit-redacted",
        ),
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.accountNumber', '9')"
            " WHERE id = 5",
            5,
            "CONTENT_HASH_MISMATCH",
            id="edit-sensitive",
        ),
        pytest.param("DELETE FROM audit_events WHERE id = 2", 3, "BROKEN_LINK", id="del-archived"),
        pytest.param("DELETE FROM audit_events WHERE id = 4", 5, "BROKEN_LINK", id="del-redacted"),
        pytest.param(
            "UPDATE audit_events SET archived = 1 WHERE id = 5", 5, "INVALID_ARCHIVE", id="archive"
        ),
    ],
)
def test_tampering_is_still_detected(
    client: TestClient, engine: Engine, statement: str, record_id: int, violation: str
) -> None:
    with Session(engine) as session:
        session.connection().exec_driver_sql(statement)
        session.commit()

    data = _json(client, "/audit/verify")

    assert data["intact"] is False
    assert data["firstBrokenRecordId"] == record_id
    assert data["violationType"] == violation


def test_tampered_export_fails_offline(client: TestClient, tmp_path: Path) -> None:
    bundle = _json(client, "/audit/export?actorId=user-1042")
    bundle["records"][1]["payload"]["accountNumber"] = "9999-TEST"  # un-redact with a fake

    result = _verify_bundle(tmp_path, bundle)

    assert result.returncode == 1
    assert "record 4: sensitive field 'accountNumber' has no salt" in result.stderr
