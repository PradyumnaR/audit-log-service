"""Unit tests for appending chained records to the audit_events table."""

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from audit_log.domain.hashing import GENESIS_HASH, compute_content_hash, compute_field_hash
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import NewEvent, append_event, latest_hash

FIXED_NOW = datetime(2026, 9, 24, 14, 32, 10, 500, tzinfo=UTC)


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _new_event(**overrides: Any) -> NewEvent:
    values: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"field": "mailingAddress", "newValue": "48 Pine Ave"},
    }
    values.update(overrides)
    return NewEvent(**values)


def _append(session: Session, **overrides: Any) -> AuditEvent:
    return append_event(
        session, _new_event(**overrides), sensitive_fields=(), now=lambda: FIXED_NOW
    )


def _recomputed_hash(record: AuditEvent) -> str:
    assert record.event_type is not None
    assert record.actor_id is not None
    assert record.resource_type is not None
    assert record.resource_id is not None
    assert record.payload is not None
    return compute_content_hash(
        event_type=record.event_type,
        actor_id=record.actor_id,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        timestamp=record.timestamp,
        payload=record.payload,
        field_hashes=record.field_hashes,
        previous_hash=record.previous_hash,
    )


def test_latest_hash_is_genesis_for_empty_table(engine: Engine) -> None:
    with Session(engine) as session:
        assert latest_hash(session) == GENESIS_HASH


def test_first_record_links_to_genesis(engine: Engine) -> None:
    with Session(engine) as session:
        record = _append(session)
        assert record.id == 1
        assert record.previous_hash == GENESIS_HASH


def test_each_record_links_to_previous_content_hash(engine: Engine) -> None:
    with Session(engine) as session:
        first = _append(session)
        second = _append(session, actor_id="user-2001")
        third = _append(session, event_type="USER_LOGIN")
        assert second.previous_hash == first.content_hash
        assert third.previous_hash == second.content_hash
        assert latest_hash(session) == third.content_hash


def test_content_hash_uses_shared_hashing_module(engine: Engine) -> None:
    with Session(engine) as session:
        record = _append(session)
        assert record.content_hash == _recomputed_hash(record)


def test_stored_values_round_trip(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session, payload={"b": 1, "a": {"y": 2, "x": 1}})
    with Session(engine) as session:
        stored = session.get_one(AuditEvent, 1)
        assert stored.event_type == "RECORD_UPDATED"
        assert stored.actor_id == "user-1042"
        assert stored.resource_type == "ACCOUNT"
        assert stored.resource_id == "acct-88731"
        assert stored.payload == {"b": 1, "a": {"y": 2, "x": 1}}
        assert stored.archived is False
        assert stored.content_hash == _recomputed_hash(stored)


def test_server_assigns_canonical_utc_timestamp(engine: Engine) -> None:
    with Session(engine) as session:
        assert _append(session).timestamp == "2026-09-24T14:32:10Z"


def test_default_clock_is_current_utc_time(engine: Engine) -> None:
    before = datetime.now(UTC).replace(microsecond=0)
    with Session(engine) as session:
        record = append_event(session, _new_event(), sensitive_fields=())
        stamped = datetime.strptime(record.timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert before <= stamped <= datetime.now(UTC)


def test_sensitive_fields_get_salted_field_hashes(engine: Engine) -> None:
    payload = {"accountNumber": "0000-TEST", "field": "mailingAddress"}
    with Session(engine) as session:
        record = append_event(
            session,
            _new_event(payload=payload),
            sensitive_fields={"accountNumber", "notPresent"},
            now=lambda: FIXED_NOW,
        )
        assert record.payload == payload
        assert set(record.field_hashes) == {"accountNumber"}
        assert set(record.field_salts) == {"accountNumber"}
        salt = record.field_salts["accountNumber"]
        assert record.field_hashes["accountNumber"] == compute_field_hash(salt, "0000-TEST")
        assert record.content_hash == _recomputed_hash(record)


def test_sensitive_fields_default_to_config(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    with Session(engine) as session:
        record = append_event(
            session, _new_event(payload={"accountNumber": "0000-TEST"}), now=lambda: FIXED_NOW
        )
        assert set(record.field_hashes) == {"accountNumber"}


def test_caller_payload_is_not_shared_with_record(engine: Engine) -> None:
    payload: dict[str, Any] = {"field": "mailingAddress"}
    with Session(engine) as session:
        record = _append(session, payload=payload)
        payload["field"] = "changed"
        assert record.payload == {"field": "mailingAddress"}


def test_archived_last_record_still_provides_link(engine: Engine) -> None:
    with Session(engine) as session:
        first = _append(session)
        first_hash = first.content_hash
        session.execute(
            text(
                "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
                " resource_type = NULL, resource_id = NULL, payload = NULL WHERE id = 1"
            )
        )
        session.commit()
        assert _append(session).previous_hash == first_hash


def test_sqlite_transactions_take_write_lock_immediately(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    engine = make_engine(f"sqlite:///{db_path}")
    create_schema(engine)
    try:
        with Session(engine) as session:
            # A plain read is enough to open the transaction and take the write lock.
            session.scalars(select(AuditEvent.id)).all()
            other = sqlite3.connect(db_path, timeout=0, isolation_level=None)
            try:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    other.execute("BEGIN IMMEDIATE")
            finally:
                other.close()
    finally:
        engine.dispose()
