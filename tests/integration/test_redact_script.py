"""Integration tests for the redaction script against a real SQLite file."""

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from audit_log.api.app import create_app
from audit_log.schema.events import REDACTED
from audit_log.storage.database import create_schema, make_engine

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "redact.py"

BODY = {
    "eventType": "RECORD_UPDATED",
    "actorId": "user-1042",
    "resourceType": "ACCOUNT",
    "resourceId": "acct-88731",
    "payload": {"accountNumber": "0000-TEST", "field": "mailingAddress"},
}


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
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as client:
        for _ in range(3):
            assert client.post("/audit/events", json=BODY).status_code == 201
        yield client


def _run_script(db_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    child_env = {**os.environ, "DATABASE_URL": db_url}
    return subprocess.run(  # noqa: S603 - fixed argv (this repo's script), no shell
        [sys.executable, str(SCRIPT), *args],
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


def _payloads(client: TestClient) -> list[dict[str, Any]]:
    return [item["payload"] for item in _json(client, "/audit/events")["items"]]


def test_script_redacts_and_verify_passes(client: TestClient, db_url: str) -> None:
    result = _run_script(db_url, "--id", "2", "--field", "accountNumber")

    assert result.returncode == 0, result.stderr
    assert _payloads(client) == [
        BODY["payload"],
        {"accountNumber": REDACTED, "field": "mailingAddress"},
        BODY["payload"],
    ]
    assert _json(client, "/audit/verify") == {"intact": True, "recordsChecked": 3}


def test_new_events_after_redaction_keep_chain_intact(client: TestClient, db_url: str) -> None:
    assert _run_script(db_url, "--id", "3", "--field", "accountNumber").returncode == 0
    assert client.post("/audit/events", json=BODY).status_code == 201

    assert _json(client, "/audit/verify") == {"intact": True, "recordsChecked": 4}


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        pytest.param(("--id", "1", "--field", "field"), 1, "not in SENSITIVE_FIELDS", id="field"),
        pytest.param(("--id", "99", "--field", "accountNumber"), 1, "does not exist", id="id"),
        pytest.param(("--id", "1"), 2, "required: --field", id="missing-field"),
        pytest.param(("--field", "accountNumber"), 2, "required: --id", id="missing-id"),
    ],
)
def test_refused_or_bad_arguments_change_nothing(
    client: TestClient, db_url: str, args: tuple[str, ...], code: int, message: str
) -> None:
    result = _run_script(db_url, *args)

    assert result.returncode == code
    assert message in result.stderr
    assert _payloads(client) == [BODY["payload"]] * 3


def test_second_redaction_is_refused(client: TestClient, db_url: str) -> None:
    assert _run_script(db_url, "--id", "1", "--field", "accountNumber").returncode == 0

    result = _run_script(db_url, "--id", "1", "--field", "accountNumber")

    assert result.returncode == 1
    assert "already redacted" in result.stderr
