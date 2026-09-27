"""Unit tests for redaction: removing a sensitive value and its salt."""

from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from audit_log.domain.verification import verify_chain
from audit_log.operations import redaction
from audit_log.schema.events import REDACTED, EventRecord
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import (
    NewEvent,
    RedactionRefusedError,
    append_event,
    iter_chain,
    redact_field,
)

SENSITIVE = ("accountNumber", "taxId")


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _append(session: Session, payload: dict[str, str] | None = None) -> AuditEvent:
    new_event = NewEvent(
        event_type="RECORD_UPDATED",
        actor_id="user-1042",
        resource_type="ACCOUNT",
        resource_id="acct-88731",
        payload=payload or {"accountNumber": "0000-TEST", "field": "mailingAddress"},
    )
    return append_event(session, new_event, sensitive_fields=SENSITIVE)


def _redact(session: Session, record_id: int, field: str = "accountNumber") -> None:
    redact_field(session, record_id, field, sensitive_fields=SENSITIVE)


def _record(session: Session, record_id: int) -> AuditEvent:
    session.expire_all()
    record = session.get(AuditEvent, record_id)
    assert record is not None
    return record


def test_removes_value_and_salt_and_keeps_hashes(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session)
        before = _record(session, 1)
        kept = (before.content_hash, before.previous_hash, dict(before.field_hashes))
        _redact(session, 1)
        record = _record(session, 1)
        assert record.payload == {"field": "mailingAddress"}
        assert record.field_salts == {}
        assert (record.content_hash, record.previous_hash, record.field_hashes) == kept


def test_only_the_named_field_is_redacted(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session, {"accountNumber": "0000-TEST", "taxId": "000-00-0000", "field": "x"})
        _redact(session, 1, "taxId")
        record = _record(session, 1)
        assert record.payload == {"accountNumber": "0000-TEST", "field": "x"}
        assert set(record.field_salts) == {"accountNumber"}


def test_chain_verifies_after_redaction(engine: Engine) -> None:
    with Session(engine) as session:
        for _ in range(3):
            _append(session)
        _redact(session, 2)
        result = verify_chain(iter_chain(session))
        assert result.intact
        assert result.records_checked == 3


def test_response_shows_redacted(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session)
        _redact(session, 1)
        payload = EventRecord.from_record(_record(session, 1)).payload
        assert payload == {"accountNumber": REDACTED, "field": "mailingAddress"}


def test_uses_sensitive_fields_config_by_default(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with Session(engine) as session:
        _append(session)
        monkeypatch.setenv("SENSITIVE_FIELDS", "taxId")
        with pytest.raises(RedactionRefusedError, match="not in SENSITIVE_FIELDS"):
            redact_field(session, 1, "accountNumber")
        monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
        redact_field(session, 1, "accountNumber")
        assert "accountNumber" not in (_record(session, 1).payload or {})


def _tamper_value(session: Session) -> None:
    session.connection().exec_driver_sql(
        "UPDATE audit_events SET payload = json_set(payload, '$.accountNumber', '9999-TEST')"
    )
    session.commit()


def _redact_first(session: Session) -> None:
    _redact(session, 1)


def _archive(session: Session) -> None:
    session.connection().exec_driver_sql(
        "UPDATE audit_events SET archived = 1, event_type = NULL, actor_id = NULL,"
        " resource_type = NULL, resource_id = NULL, payload = NULL,"
        " field_hashes = '{}', field_salts = '{}'"
    )
    session.commit()


@pytest.mark.parametrize(
    ("record_id", "field", "setup", "message"),
    [
        pytest.param(1, "field", None, "not in SENSITIVE_FIELDS", id="not-sensitive"),
        pytest.param(9, "accountNumber", None, "does not exist", id="missing-record"),
        pytest.param(1, "taxId", None, "no sensitive field 'taxId'", id="field-absent"),
        pytest.param(1, "accountNumber", _archive, "archived", id="archived"),
        pytest.param(1, "accountNumber", _redact_first, "already redacted", id="already-redacted"),
        pytest.param(1, "accountNumber", _tamper_value, "does not match", id="tampered"),
    ],
)
def test_refusals_change_nothing(
    engine: Engine,
    record_id: int,
    field: str,
    setup: Callable[[Session], None] | None,
    message: str,
) -> None:
    with Session(engine) as session:
        _append(session)
        if setup is not None:
            setup(session)
        snapshot = session.execute(select(AuditEvent.__table__)).all()
        with pytest.raises(RedactionRefusedError, match=message):
            _redact(session, record_id, field)
        session.expire_all()
        assert session.execute(select(AuditEvent.__table__)).all() == snapshot


def test_main_redacts_and_reports(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    with Session(engine) as session:
        _append(session)
    assert redaction.main(["--id", "1", "--field", "accountNumber"], engine) == 0
    assert "redacted field 'accountNumber' of record 1" in capsys.readouterr().out
    with Session(engine) as session:
        assert _record(session, 1).field_salts == {}


def test_main_refusal_exits_1(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", "accountNumber")
    with Session(engine) as session:
        _append(session)
    assert redaction.main(["--id", "1", "--field", "field"], engine) == 1
    assert "refused: field 'field' is not in SENSITIVE_FIELDS" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        pytest.param([], "the following arguments are required: --id, --field", id="missing"),
        pytest.param(["--id", "1"], "required: --field", id="missing-field"),
        pytest.param(["--id", "0", "--field", "x"], "positive integer", id="zero"),
        pytest.param(["--id", "-1", "--field", "x"], "--id", id="negative"),
        pytest.param(["--id", "abc", "--field", "x"], "positive integer", id="not-a-number"),
    ],
)
def test_main_rejects_bad_arguments(
    engine: Engine, capsys: pytest.CaptureFixture[str], argv: list[str], message: str
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        redaction.main(argv, engine)
    assert exit_info.value.code == 2
    assert message in capsys.readouterr().err
