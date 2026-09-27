"""Unit tests for POST /audit/events request validation."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from audit_log.schema.events import MAX_PAYLOAD_BYTES, EventCreate
from audit_log.storage.repository import NewEvent


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-1042",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-88731",
        "payload": {"field": "mailingAddress", "newValue": "48 Pine Ave"},
    }
    body.update(overrides)
    return body


def _without(key: str) -> dict[str, Any]:
    body = _body()
    del body[key]
    return body


def test_valid_body_maps_to_new_event() -> None:
    event = EventCreate.model_validate_json(json.dumps(_body()))
    assert event.to_new_event() == NewEvent(
        event_type="RECORD_UPDATED",
        actor_id="user-1042",
        resource_type="ACCOUNT",
        resource_id="acct-88731",
        payload={"field": "mailingAddress", "newValue": "48 Pine Ave"},
    )


@pytest.mark.parametrize("value", ["USER_LOGIN", "A", "V2_EVENT", "X" * 64])
def test_accepts_upper_snake_case_types(value: str) -> None:
    EventCreate.model_validate(_body(eventType=value, resourceType=value))


@pytest.mark.parametrize("field", ["eventType", "resourceType"])
@pytest.mark.parametrize(
    "value",
    ["", "user_login", "UserLogin", "_LOGIN", "LOGIN_", "USER__LOGIN", "1LOGIN", "A-B", "X" * 65],
)
def test_rejects_badly_formatted_types(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        EventCreate.model_validate(_body(**{field: value}))


@pytest.mark.parametrize("field", ["actorId", "resourceId"])
@pytest.mark.parametrize("value", ["", " ", " user-1", "user-1 ", "user\n1", "x" * 256])
def test_rejects_bad_identifiers(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        EventCreate.model_validate(_body(**{field: value}))


@pytest.mark.parametrize("field", ["actorId", "resourceId"])
def test_accepts_identifier_at_max_length(field: str) -> None:
    EventCreate.model_validate(_body(**{field: "x" * 255}))


@pytest.mark.parametrize("field", ["eventType", "actorId", "resourceType", "resourceId", "payload"])
def test_rejects_missing_field(field: str) -> None:
    with pytest.raises(ValidationError):
        EventCreate.model_validate(_without(field))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actorId", 1042),
        ("resourceId", None),
        ("eventType", ["USER_LOGIN"]),
        ("payload", "not-an-object"),
        ("payload", ["a", "b"]),
    ],
)
def test_rejects_wrong_types(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        EventCreate.model_validate(_body(**{field: value}))


@pytest.mark.parametrize("extra", ["timestamp", "id", "contentHash", "previousHash", "archived"])
def test_rejects_unknown_and_server_owned_fields(extra: str) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        EventCreate.model_validate(_body(**{extra: "2026-09-24T14:32:10Z"}))


def test_rejects_snake_case_field_names() -> None:
    body = _without("eventType")
    body["event_type"] = "USER_LOGIN"
    with pytest.raises(ValidationError):
        EventCreate.model_validate(body)


def test_accepts_empty_payload() -> None:
    assert EventCreate.model_validate(_body(payload={})).payload == {}


def test_payload_at_size_limit_is_accepted() -> None:
    # {"k":"<filler>"} is 8 bytes of JSON around the filler.
    EventCreate.model_validate(_body(payload={"k": "x" * (MAX_PAYLOAD_BYTES - 8)}))


def test_oversized_payload_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at most"):
        EventCreate.model_validate(_body(payload={"k": "x" * (MAX_PAYLOAD_BYTES - 7)}))


def test_payload_size_counts_utf8_bytes() -> None:
    # "é" is 2 bytes in UTF-8, so this is over the limit despite being under it in characters.
    with pytest.raises(ValidationError, match="at most"):
        EventCreate.model_validate(_body(payload={"k": "é" * (MAX_PAYLOAD_BYTES // 2)}))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_numbers_in_payload(value: float) -> None:
    with pytest.raises(ValidationError, match="NaN or Infinity"):
        EventCreate.model_validate(_body(payload={"nested": {"amount": value}}))
