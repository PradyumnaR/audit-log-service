"""Unit tests for the audit_events table definition."""

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from audit_log.domain.hashing import GENESIS_HASH
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _row(**overrides: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"field": "mailingAddress"},
        "timestamp": "2026-09-24T14:32:10Z",
        "content_hash": "a" * 64,
        "previous_hash": GENESIS_HASH,
    }
    values.update(overrides)
    return AuditEvent(**values)


def test_table_has_expected_snake_case_columns(engine: Engine) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("audit_events")}
    assert columns == {
        "id",
        "event_type",
        "actor_id",
        "resource_type",
        "resource_id",
        "payload",
        "timestamp",
        "content_hash",
        "previous_hash",
        "archived",
        "field_hashes",
        "field_salts",
    }


def test_query_indexes_exist(engine: Engine) -> None:
    indexes = {index["name"] for index in inspect(engine).get_indexes("audit_events")}
    assert {
        "ix_audit_events_actor_id",
        "ix_audit_events_resource",
        "ix_audit_events_event_type",
        "ix_audit_events_timestamp",
    } <= indexes


def test_row_round_trips_with_defaults(engine: Engine) -> None:
    with Session(engine) as session:
        session.add(_row(payload={"accountNumber": "123", "nested": {"b": 1, "a": 2}}))
        session.commit()
        stored = session.get_one(AuditEvent, 1)
        assert stored.payload == {"accountNumber": "123", "nested": {"b": 1, "a": 2}}
        assert stored.archived is False
        assert stored.field_hashes == {}
        assert stored.field_salts == {}


def test_ids_are_increasing_and_never_reused(engine: Engine) -> None:
    with Session(engine) as session:
        session.add_all([_row(), _row()])
        session.commit()
        session.execute(text("DELETE FROM audit_events WHERE id = 2"))
        session.add(_row())
        session.commit()
        ids = session.scalars(text("SELECT id FROM audit_events ORDER BY id")).all()
    assert ids == [1, 3]


@pytest.mark.parametrize(
    "column", ["event_type", "actor_id", "resource_type", "resource_id", "payload"]
)
def test_content_required_unless_archived(engine: Engine, column: str) -> None:
    with Session(engine) as session:
        session.add(_row(**{column: None}))
        with pytest.raises(IntegrityError):
            session.commit()


def test_archived_row_may_have_cleared_content(engine: Engine) -> None:
    cleared = {
        "event_type": None,
        "actor_id": None,
        "resource_type": None,
        "resource_id": None,
        "payload": None,
    }
    with Session(engine) as session:
        session.add(_row(archived=True, **cleared))
        session.commit()
        assert session.get_one(AuditEvent, 1).archived is True


@pytest.mark.parametrize("column", ["timestamp", "content_hash", "previous_hash"])
def test_chain_columns_always_required(engine: Engine, column: str) -> None:
    with Session(engine) as session:
        session.add(_row(**{column: None}))
        with pytest.raises(IntegrityError):
            session.commit()
