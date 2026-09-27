"""Unit tests for GET /audit/events query validation and response mapping."""

from typing import Any

import pytest
from pydantic import ValidationError

from audit_log.schema.events import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    REDACTED,
    EventQuery,
    EventRecord,
)
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import EventFilter


def _query(**params: Any) -> EventQuery:
    # Query strings arrive as text, so validate string values as FastAPI does.
    return EventQuery.model_validate(params)


def test_defaults() -> None:
    query = _query()
    assert query.limit == DEFAULT_LIMIT
    assert query.after_id is None
    assert query.to_filter() == EventFilter()


def test_filters_map_to_event_filter() -> None:
    query = _query(
        eventType="RECORD_UPDATED",
        actorId="user-1042",
        resourceType="ACCOUNT",
        resourceId="acct-88731",
        **{"from": "2026-09-24T00:00:00Z"},
        to="2026-09-25T00:00:00Z",
    )
    assert query.to_filter() == EventFilter(
        event_type="RECORD_UPDATED",
        actor_id="user-1042",
        resource_type="ACCOUNT",
        resource_id="acct-88731",
        from_timestamp="2026-09-24T00:00:00Z",
        to_timestamp="2026-09-25T00:00:00Z",
    )


def test_resource_type_alone_is_allowed() -> None:
    assert _query(resourceType="ACCOUNT").to_filter() == EventFilter(resource_type="ACCOUNT")


def test_resource_id_requires_resource_type() -> None:
    with pytest.raises(ValidationError, match="resourceId requires resourceType"):
        _query(resourceId="acct-88731")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventType", "user_login"),
        ("resourceType", "Account"),
        ("actorId", ""),
        ("actorId", " user-1"),
        ("actorId", "x" * 256),
        ("resourceId", "acct 1 "),
    ],
)
def test_rejects_badly_formatted_filters(field: str, value: str) -> None:
    # resourceType is always set so resourceId-without-type is not what fails.
    params = {"resourceType": "ACCOUNT", field: value}
    with pytest.raises(ValidationError):
        _query(**params)


@pytest.mark.parametrize("extra", ["actorID", "resource_type", "timestamp", "offset"])
def test_rejects_unknown_parameters(extra: str) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _query(**{extra: "x"})


@pytest.mark.parametrize(
    ("value", "stored"),
    [
        ("2026-09-24T14:32:10Z", "2026-09-24T14:32:10Z"),
        ("2026-09-24T16:32:10+02:00", "2026-09-24T14:32:10Z"),
        ("2026-09-24T14:32:10.000001Z", "2026-09-24T14:32:11Z"),
    ],
)
def test_time_bounds_normalize_to_stored_format(value: str, stored: str) -> None:
    event_filter = _query(**{"from": value}, to="2030-01-01T00:00:00Z").to_filter()
    assert event_filter.from_timestamp == stored
    assert _query(to=value).to_filter().to_timestamp == stored


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-24T14:32:10",  # no offset
        "2026-09-24",
        "1727188330",  # Unix epoch
        "2026-13-01T00:00:00Z",
        "2026-09-24 14:32:10Z",
        "yesterday",
    ],
)
@pytest.mark.parametrize("field", ["from", "to"])
def test_rejects_bad_time_bounds(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _query(**{field: value})


@pytest.mark.parametrize("to", ["2026-09-24T00:00:00Z", "2026-09-23T23:59:59Z"])
def test_from_must_be_earlier_than_to(to: str) -> None:
    with pytest.raises(ValidationError, match="from must be earlier than to"):
        _query(**{"from": "2026-09-24T00:00:00Z"}, to=to)


@pytest.mark.parametrize("limit", ["1", str(MAX_LIMIT)])
def test_accepts_limit_in_range(limit: str) -> None:
    assert _query(limit=limit).limit == int(limit)


@pytest.mark.parametrize("limit", ["0", "-1", str(MAX_LIMIT + 1), "ten", "1.5"])
def test_rejects_limit_out_of_range(limit: str) -> None:
    with pytest.raises(ValidationError):
        _query(limit=limit)


def test_cursor_is_record_id() -> None:
    assert _query(cursor="42").after_id == 42


@pytest.mark.parametrize("cursor", ["0", "-1", "01", "abc", "1.0", "", "1" * 20])
def test_rejects_bad_cursor(cursor: str) -> None:
    with pytest.raises(ValidationError):
        _query(cursor=cursor)


def _record(**overrides: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "id": 3,
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"field": "mailingAddress"},
        "timestamp": "2026-09-24T14:32:10Z",
        "content_hash": "c" * 64,
        "previous_hash": "p" * 64,
        "archived": False,
        "field_hashes": {},
        "field_salts": {},
    }
    values.update(overrides)
    return AuditEvent(**values)


def test_record_maps_to_camel_case_response() -> None:
    body = EventRecord.from_record(_record()).model_dump(by_alias=True)
    assert body == {
        "id": 3,
        "eventType": "RECORD_UPDATED",
        "actorId": "user-1042",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-88731",
        "payload": {"field": "mailingAddress"},
        "timestamp": "2026-09-24T14:32:10Z",
        "contentHash": "c" * 64,
        "previousHash": "p" * 64,
    }


def test_unredacted_sensitive_value_is_shown() -> None:
    record = _record(
        payload={"accountNumber": "0000-TEST"},
        field_hashes={"accountNumber": "h" * 64},
        field_salts={"accountNumber": "s" * 64},
    )
    assert EventRecord.from_record(record).payload == {"accountNumber": "0000-TEST"}


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"field": "x"}, id="value-removed"),
        pytest.param({"field": "x", "accountNumber": "0000-TEST"}, id="salt-removed"),
    ],
)
def test_redacted_sensitive_value_is_masked(payload: dict[str, Any]) -> None:
    record = _record(payload=payload, field_hashes={"accountNumber": "h" * 64}, field_salts={})
    result = EventRecord.from_record(record)
    assert result.payload == {"field": "x", "accountNumber": REDACTED}
    assert record.payload == payload  # stored record untouched


def test_archived_record_cannot_be_mapped() -> None:
    record = _record(archived=True, event_type=None, payload=None)
    with pytest.raises(ValueError, match="archived"):
        EventRecord.from_record(record)
