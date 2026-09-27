"""Unit tests for retention: archiving records older than the retention window."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from audit_log.domain.verification import ViolationType, verify_chain
from audit_log.operations import retention
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import (
    EventFilter,
    NewEvent,
    append_event,
    archive_expired,
    iter_chain,
    query_events,
)

NOW = datetime(2026, 9, 27, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _append_at(
    session: Session, moment: datetime, *, sensitive_fields: tuple[str, ...] = ()
) -> AuditEvent:
    new_event = NewEvent(
        event_type="RECORD_UPDATED",
        actor_id="user-1042",
        resource_type="ACCOUNT",
        resource_id="acct-88731",
        payload={"accountNumber": "0000-TEST", "field": "mailingAddress"},
    )
    return append_event(session, new_event, sensitive_fields=sensitive_fields, now=lambda: moment)


def _seed(session: Session, ages_in_days: list[float]) -> None:
    for age in ages_in_days:
        _append_at(session, NOW - timedelta(days=age), sensitive_fields=("accountNumber",))


def _archive(session: Session, days: int) -> int:
    return archive_expired(session, days, now=lambda: NOW)


def _chain(session: Session) -> list[AuditEvent]:
    return list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))


def test_archives_only_records_older_than_window(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 31, 29, 1])
        assert _archive(session, 30) == 2
        assert [record.archived for record in _chain(session)] == [True, True, False, False]


def test_archived_records_keep_only_chain_link(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 1])
        before = _chain(session)[0]
        kept = (before.id, before.timestamp, before.content_hash, before.previous_hash)
        _archive(session, 30)
        session.expire_all()
        record = _chain(session)[0]
        assert (record.id, record.timestamp, record.content_hash, record.previous_hash) == kept
        assert record.event_type is None
        assert record.actor_id is None
        assert record.resource_type is None
        assert record.resource_id is None
        assert record.payload is None
        assert record.field_hashes == {}
        assert record.field_salts == {}


def test_live_records_are_untouched(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 1])
        live = _chain(session)[1]
        snapshot = (live.payload, live.field_hashes, live.field_salts, live.content_hash)
        _archive(session, 30)
        session.expire_all()
        live = _chain(session)[1]
        assert (live.payload, live.field_hashes, live.field_salts, live.content_hash) == snapshot


def test_record_exactly_at_cutoff_is_kept(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [30])
        assert _archive(session, 30) == 0
        assert _chain(session)[0].archived is False


def test_nothing_expired_archives_nothing(engine: Engine) -> None:
    with Session(engine) as session:
        assert _archive(session, 30) == 0
        _seed(session, [5, 1])
        assert _archive(session, 30) == 0


def test_rerun_only_counts_newly_archived(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 20, 1])
        assert _archive(session, 30) == 1
        assert _archive(session, 30) == 0
        assert _archive(session, 10) == 1
        assert [record.archived for record in _chain(session)] == [True, True, False]


def test_rejects_non_positive_window(engine: Engine) -> None:
    with Session(engine) as session, pytest.raises(ValueError, match="at least 1"):
        _archive(session, 0)


@pytest.mark.parametrize("days", [1, 10, 30, 365])
def test_chain_verifies_after_retention(engine: Engine, days: int) -> None:
    with Session(engine) as session:
        _seed(session, [400, 100, 40, 31, 29, 1, 0])
        _archive(session, days)
        result = verify_chain(iter_chain(session))
        assert result.intact
        assert result.records_checked == 7


def test_fully_archived_chain_verifies_and_new_records_link(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 35])
        assert _archive(session, 30) == 2
        last_hash = _chain(session)[-1].content_hash
        assert _append_at(session, NOW).previous_hash == last_hash
        assert verify_chain(iter_chain(session)).intact


def test_archived_flag_set_after_live_record_is_invalid_archive(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 20, 10, 1])
        _archive(session, 30)
        # Tamper: hide a later record by archiving it out of order.
        _chain(session)[2].archived = True
        session.commit()
        result = verify_chain(iter_chain(session))
        assert result.violation is not None
        assert result.violation.record_id == 3
        assert result.violation.violation_type is ViolationType.INVALID_ARCHIVE


def test_archived_records_are_not_queried(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 1])
        _archive(session, 30)
        page = query_events(session, EventFilter(), limit=10)
        assert [record.id for record in page.records] == [2]


def test_run_retention_uses_engine(engine: Engine) -> None:
    with Session(engine) as session:
        _seed(session, [40, 1])
    assert retention.run_retention(engine, 30, now=lambda: NOW) == 1


def test_main_reports_archived_count(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with Session(engine) as session:
        _seed(session, [4000, 3000])
    monkeypatch.setenv("RETENTION_DAYS", "30")
    assert retention.main(engine) == 0
    assert "archived 2 record(s) older than 30 day(s)" in capsys.readouterr().out


def test_main_fails_without_retention_days(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("RETENTION_DAYS", raising=False)
    assert retention.main() == 1
    assert "RETENTION_DAYS is not set" in capsys.readouterr().err
