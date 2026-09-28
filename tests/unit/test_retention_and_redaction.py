"""Unit tests for a chain with both archived and redacted records (scenario B5)."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from audit_log.domain.verification import ViolationType, verify_chain
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import (
    NewEvent,
    append_event,
    archive_before,
    iter_chain,
    redact_field,
)

NOW = datetime(2026, 9, 27, 10, 0, 0, tzinfo=UTC)
SENSITIVE = ("accountNumber", "taxId")
AGES_IN_DAYS = [90, 60, 45, 20, 10, 5, 1]  # ids 1-7; ids 1-3 are archived at 30 days


def _clock(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """Chain of 7: ids 1-3 archived, id 4 and 6 have accountNumber redacted."""
    with Session(engine) as session:
        for age in AGES_IN_DAYS:
            new_event = NewEvent(
                event_type="RECORD_UPDATED",
                actor_id="user-1042",
                resource_type="ACCOUNT",
                resource_id="acct-88731",
                payload={"accountNumber": "0000-TEST", "taxId": "000-00-0000", "field": "x"},
            )
            append_event(
                session,
                new_event,
                sensitive_fields=SENSITIVE,
                now=_clock(NOW - timedelta(days=age)),
            )
        redact_field(session, 2, "accountNumber", sensitive_fields=SENSITIVE)  # later archived
        assert archive_before(session, NOW - timedelta(days=30)) == 3
        redact_field(session, 4, "accountNumber", sensitive_fields=SENSITIVE)
        redact_field(session, 6, "accountNumber", sensitive_fields=SENSITIVE)
        yield session


def _sql(session: Session, statement: str) -> None:
    session.connection().exec_driver_sql(statement)
    session.commit()
    session.expire_all()


def _violation(session: Session) -> tuple[int, ViolationType]:
    result = verify_chain(iter_chain(session))
    assert result.violation is not None, "expected tampering to be detected"
    return result.violation.record_id, result.violation.violation_type


def test_chain_with_archived_and_redacted_records_verifies(session: Session) -> None:
    records = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    assert [record.archived for record in records] == [True] * 3 + [False] * 4
    assert ["accountNumber" in (record.payload or {}) for record in records[3:]] == [
        False,
        True,
        False,
        True,
    ]
    result = verify_chain(iter_chain(session))
    assert result.intact
    assert result.records_checked == 7


def test_appends_after_both_keep_chain_intact(session: Session) -> None:
    new_event = NewEvent("RECORD_UPDATED", "user-1042", "ACCOUNT", "acct-88731", {"f": 1})
    append_event(session, new_event, sensitive_fields=SENSITIVE, now=lambda: NOW)
    assert verify_chain(iter_chain(session)).records_checked == 8
    assert verify_chain(iter_chain(session)).intact


MISMATCH = ViolationType.CONTENT_HASH_MISMATCH


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.field', 'y') WHERE id = 4",
            (4, MISMATCH),
            id="edit-redacted-record",
        ),
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.taxId', '999') WHERE id = 4",
            (4, MISMATCH),
            id="edit-unredacted-sensitive-value-of-redacted-record",
        ),
        pytest.param(
            "UPDATE audit_events SET payload = json_set(payload, '$.accountNumber', '9')"
            " WHERE id = 5",
            (5, MISMATCH),
            id="edit-unredacted-sensitive-value",
        ),
        pytest.param(
            "UPDATE audit_events SET field_hashes = json_set(field_hashes, '$.accountNumber',"
            " '0000000000000000000000000000000000000000000000000000000000000000') WHERE id = 6",
            (6, MISMATCH),
            id="edit-field-hash-of-redacted",
        ),
        pytest.param(
            "UPDATE audit_events SET field_hashes = '{}' WHERE id = 6",
            (6, MISMATCH),
            id="drop-field-hashes-of-redacted",
        ),
        pytest.param(
            "UPDATE audit_events SET actor_id = 'user-2001' WHERE id = 7",
            (7, MISMATCH),
            id="edit-live-record",
        ),
        pytest.param(
            "UPDATE audit_events SET content_hash = previous_hash WHERE id = 2",
            (3, ViolationType.BROKEN_LINK),
            id="edit-archived-hash",
        ),
        pytest.param(
            "DELETE FROM audit_events WHERE id = 2",
            (3, ViolationType.BROKEN_LINK),
            id="del-archived",
        ),
        pytest.param(
            "DELETE FROM audit_events WHERE id = 4",
            (5, ViolationType.BROKEN_LINK),
            id="del-redacted",
        ),
        pytest.param(
            "DELETE FROM audit_events WHERE id = 3",
            (4, ViolationType.BROKEN_LINK),
            id="del-last-archived",
        ),
        pytest.param(
            "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
            " resource_type = NULL, resource_id = NULL, payload = NULL,"
            " field_hashes = '{}', field_salts = '{}' WHERE id = 6",
            (6, ViolationType.INVALID_ARCHIVE),
            id="archive-redacted-out-of-order",
        ),
    ],
)
def test_tampering_is_still_detected(
    session: Session, statement: str, expected: tuple[int, ViolationType]
) -> None:
    _sql(session, statement)
    assert _violation(session) == expected
