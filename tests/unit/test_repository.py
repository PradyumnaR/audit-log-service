"""Unit tests for appending chained records to the audit_events table."""

import sqlite3
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from audit_log.domain.hashing import GENESIS_HASH, compute_content_hash, compute_field_hash
from audit_log.storage import repository
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import (
    EventFilter,
    NewEvent,
    append_event,
    iter_chain,
    latest_hash,
    query_events,
)

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


def _archive(session: Session, record_id: int) -> None:
    session.execute(
        text(
            "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
            " resource_type = NULL, resource_id = NULL, payload = NULL WHERE id = :id"
        ),
        {"id": record_id},
    )
    session.commit()


def _clock(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


def _ids(session: Session, event_filter: EventFilter, **kwargs: Any) -> list[int]:
    kwargs.setdefault("limit", 100)
    return [record.id for record in query_events(session, event_filter, **kwargs).records]


def test_query_returns_all_records_in_id_order(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(3):
            _append(session)
        assert _ids(session, EventFilter()) == [1, 2, 3]


def test_query_on_empty_table(engine: Engine) -> None:
    with Session(engine) as session:
        page = query_events(session, EventFilter(), limit=10)
        assert page.records == []
        assert page.next_after_id is None


@pytest.mark.parametrize(
    ("event_filter", "expected"),
    [
        pytest.param(EventFilter(event_type="USER_LOGIN"), [2], id="event-type"),
        pytest.param(EventFilter(actor_id="user-2001"), [3], id="actor"),
        pytest.param(EventFilter(resource_type="USER"), [4], id="resource-type"),
        pytest.param(
            EventFilter(resource_type="ACCOUNT", resource_id="acct-2"), [3], id="resource"
        ),
        pytest.param(
            EventFilter(resource_type="USER", resource_id="acct-88731"), [], id="id-other-type"
        ),
        pytest.param(
            EventFilter(resource_type="ACCOUNT", actor_id="user-1042"), [1, 2], id="combined"
        ),
    ],
)
def test_query_filters(engine: Engine, event_filter: EventFilter, expected: list[int]) -> None:
    with Session(engine) as session:
        _append(session)
        _append(session, event_type="USER_LOGIN")
        _append(session, actor_id="user-2001", resource_id="acct-2")
        _append(session, actor_id="user-3001", resource_type="USER", resource_id="acct-2")
        assert _ids(session, event_filter) == expected


def test_query_time_range_is_from_inclusive_to_exclusive(engine: Engine) -> None:
    times = [datetime(2026, 9, 24, 10, minute, tzinfo=UTC) for minute in (0, 1, 2)]
    with Session(engine) as session:
        for moment in times:
            append_event(session, _new_event(), sensitive_fields=(), now=_clock(moment))
        window = EventFilter(from_timestamp="2026-09-24T10:01:00Z")
        assert _ids(session, window) == [2, 3]
        window = EventFilter(to_timestamp="2026-09-24T10:01:00Z")
        assert _ids(session, window) == [1]
        window = EventFilter(
            from_timestamp="2026-09-24T10:00:00Z", to_timestamp="2026-09-24T10:02:00Z"
        )
        assert _ids(session, window) == [1, 2]


def test_query_pages_with_after_id(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(5):
            _append(session)
        first = query_events(session, EventFilter(), limit=2)
        assert [record.id for record in first.records] == [1, 2]
        assert first.next_after_id == 2
        second = query_events(session, EventFilter(), limit=2, after_id=first.next_after_id)
        assert [record.id for record in second.records] == [3, 4]
        assert second.next_after_id == 4
        last = query_events(session, EventFilter(), limit=2, after_id=second.next_after_id)
        assert [record.id for record in last.records] == [5]
        assert last.next_after_id is None


def test_query_exact_final_page_has_no_next(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(2):
            _append(session)
        assert query_events(session, EventFilter(), limit=2).next_after_id is None


def test_query_pages_skip_non_matching_records(engine: Engine) -> None:
    with Session(engine) as session:
        for actor in ["a", "b", "a", "b", "a"]:
            _append(session, actor_id=actor)
        page = query_events(session, EventFilter(actor_id="a"), limit=1, after_id=1)
        assert [record.id for record in page.records] == [3]
        assert page.next_after_id == 3


def test_query_excludes_archived_records(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(3):
            _append(session)
        _archive(session, 1)
        assert _ids(session, EventFilter()) == [2, 3]
        assert _ids(session, EventFilter(actor_id="user-1042")) == [2, 3]


def test_query_rejects_non_positive_limit(engine: Engine) -> None:
    with Session(engine) as session, pytest.raises(ValueError, match="limit"):
        query_events(session, EventFilter(), limit=0)


def test_iter_chain_yields_all_records_in_id_order(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(3):
            _append(session)
        _archive(session, 1)
        records = list(iter_chain(session))
        assert [record.id for record in records] == [1, 2, 3]
        assert [record.archived for record in records] == [True, False, False]


def test_iter_chain_empty_table(engine: Engine) -> None:
    with Session(engine) as session:
        assert list(iter_chain(session)) == []


def test_iter_chain_streams_across_batches(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repository, "CHAIN_BATCH_SIZE", 2)
    with Session(engine) as session:
        for _ in range(5):
            _append(session)
        assert [record.id for record in iter_chain(session)] == [1, 2, 3, 4, 5]
