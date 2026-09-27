"""Unit tests for canonical serialization and content/field hashing."""

import hashlib
import json
import math
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from audit_log.domain import hashing
from audit_log.domain.hashing import (
    GENESIS_HASH,
    canonical_json,
    compute_content_hash,
    compute_field_hash,
    field_hash_matches,
    format_timestamp,
    generate_salt,
    hashable_payload,
    protect_sensitive_fields,
)

SALT = "00" * 32
OTHER_SALT = "11" * 32


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "timestamp": "2026-09-24T14:32:10Z",
        "payload": {"field": "mailingAddress", "oldValue": "12 Oak St", "newValue": "48 Pine Ave"},
        "field_hashes": {},
        "previous_hash": GENESIS_HASH,
    }
    event.update(overrides)
    return event


# --- canonical JSON -------------------------------------------------------------------


def test_canonical_json_sorts_keys_and_strips_whitespace() -> None:
    assert canonical_json({"b": 1, "a": {"d": [1, 2], "c": None}}) == (
        '{"a":{"c":null,"d":[1,2]},"b":1}'
    )


def test_canonical_json_keeps_non_ascii_as_utf8() -> None:
    assert canonical_json({"name": "Zoë"}) == '{"name":"Zoë"}'


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": math.nan})


# --- timestamps -----------------------------------------------------------------------


def test_format_timestamp_converts_to_utc_with_z() -> None:
    moment = datetime(2026, 9, 24, 16, 32, 10, 999, tzinfo=timezone(timedelta(hours=2)))
    assert format_timestamp(moment) == "2026-09-24T14:32:10Z"


def test_format_timestamp_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_timestamp(datetime(2026, 9, 24, 14, 32, 10))


def test_format_timestamp_accepts_utc() -> None:
    assert format_timestamp(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2026-01-02T03:04:05Z"


# --- genesis --------------------------------------------------------------------------


def test_genesis_is_fractional_sqrt_of_first_eight_primes() -> None:
    primes = [2, 3, 5, 7, 11, 13, 17, 19]
    words = [int((math.sqrt(p) % 1) * 2**32) for p in primes]
    assert "".join(f"{w:08x}" for w in words) == GENESIS_HASH


# --- content hash ---------------------------------------------------------------------


def test_content_hash_is_sha256_hex() -> None:
    digest = compute_content_hash(**_event())
    assert len(digest) == 64
    assert int(digest, 16) >= 0


def test_content_hash_is_deterministic() -> None:
    assert compute_content_hash(**_event()) == compute_content_hash(**_event())


def test_content_hash_ignores_payload_key_order() -> None:
    forward = _event(payload={"a": 1, "b": {"x": 1, "y": 2}, "c": [1, 2]})
    backward = _event(payload={"c": [1, 2], "b": {"y": 2, "x": 1}, "a": 1})
    assert compute_content_hash(**forward) == compute_content_hash(**backward)


def test_content_hash_ignores_field_hash_key_order() -> None:
    forward = _event(field_hashes={"a": "1" * 64, "b": "2" * 64})
    backward = _event(field_hashes={"b": "2" * 64, "a": "1" * 64})
    assert compute_content_hash(**forward) == compute_content_hash(**backward)


def test_content_hash_matches_documented_canonical_form() -> None:
    event = _event()
    expected_content = {
        "eventType": event["event_type"],
        "actorId": event["actor_id"],
        "resourceType": event["resource_type"],
        "resourceId": event["resource_id"],
        "timestamp": event["timestamp"],
        "payload": event["payload"],
        "fieldHashes": {},
        "previousHash": event["previous_hash"],
    }
    serialized = json.dumps(expected_content, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    assert compute_content_hash(**event) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_type", "RECORD_CREATED"),
        ("actor_id", "user-9999"),
        ("resource_type", "USER"),
        ("resource_id", "acct-00001"),
        ("timestamp", "2026-09-24T14:32:11Z"),
        ("payload", {"field": "mailingAddress", "oldValue": "12 Oak St", "newValue": "X"}),
        ("payload", {"field": "mailingAddress", "oldValue": "12 Oak St"}),
        ("payload", {"field": "mailingAddress", "oldValue": "12 Oak St", "newValue": 1}),
        ("field_hashes", {"accountNumber": "a" * 64}),
        ("previous_hash", "f" * 64),
    ],
)
def test_changing_any_hashed_field_changes_content_hash(field: str, value: Any) -> None:
    assert compute_content_hash(**_event()) != compute_content_hash(**_event(**{field: value}))


# --- field hashes ---------------------------------------------------------------------


def test_generate_salt_is_random_32_bytes() -> None:
    salts = {generate_salt() for _ in range(10)}
    assert len(salts) == 10
    assert all(len(bytes.fromhex(salt)) == 32 for salt in salts)


def test_field_hash_is_sha256_of_salt_bytes_plus_canonical_value() -> None:
    value = {"b": 2, "a": 1}
    expected = hashlib.sha256(bytes.fromhex(SALT) + b'{"a":1,"b":2}').hexdigest()
    assert compute_field_hash(SALT, value) == expected


def test_field_hash_depends_on_salt_and_value() -> None:
    base = compute_field_hash(SALT, "123456789")
    assert compute_field_hash(OTHER_SALT, "123456789") != base
    assert compute_field_hash(SALT, "123456780") != base


@pytest.mark.parametrize("salt", ["00" * 31, "zz" * 32])
def test_field_hash_rejects_bad_salt(salt: str) -> None:
    with pytest.raises(ValueError):
        compute_field_hash(salt, "value")


def test_field_hash_matches_value_salt_and_rejects_bad_salt() -> None:
    field_hash = compute_field_hash(SALT, "123456789")
    assert field_hash_matches(SALT, "123456789", field_hash)
    assert not field_hash_matches(SALT, "123456780", field_hash)
    assert not field_hash_matches(OTHER_SALT, "123456789", field_hash)
    assert not field_hash_matches("not-hex", "123456789", field_hash)


def test_protect_sensitive_fields_only_covers_present_sensitive_keys() -> None:
    payload = {"accountNumber": "123456789", "field": "mailingAddress"}
    protected = protect_sensitive_fields(payload, {"accountNumber", "taxId"})
    assert protected.field_hashes.keys() == {"accountNumber"}
    assert protected.field_salts.keys() == {"accountNumber"}
    salt = protected.field_salts["accountNumber"]
    assert protected.field_hashes["accountNumber"] == compute_field_hash(salt, "123456789")


def test_protect_sensitive_fields_uses_fresh_salt_per_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    salts = iter([SALT, OTHER_SALT])
    monkeypatch.setattr(hashing, "generate_salt", lambda: next(salts))
    payload = {"accountNumber": "123456789"}
    first = protect_sensitive_fields(payload, ["accountNumber"])
    second = protect_sensitive_fields(payload, ["accountNumber"])
    assert first.field_salts != second.field_salts
    assert first.field_hashes != second.field_hashes


def test_hashable_payload_drops_sensitive_keys() -> None:
    payload = {"accountNumber": "123456789", "field": "mailingAddress"}
    assert hashable_payload(payload, {"accountNumber": "a" * 64}) == {"field": "mailingAddress"}


def test_content_hash_uses_field_hash_not_raw_sensitive_value() -> None:
    field_hash = compute_field_hash(SALT, "123456789")
    original = _event(
        payload={"accountNumber": "123456789", "field": "mailingAddress"},
        field_hashes={"accountNumber": field_hash},
    )
    changed_value = _event(
        payload={"accountNumber": "999999999", "field": "mailingAddress"},
        field_hashes={"accountNumber": field_hash},
    )
    assert compute_content_hash(**original) == compute_content_hash(**changed_value)


def test_content_hash_survives_redaction() -> None:
    field_hash = compute_field_hash(SALT, "123456789")
    before = _event(
        payload={"accountNumber": "123456789", "field": "mailingAddress"},
        field_hashes={"accountNumber": field_hash},
    )
    redacted = _event(
        payload={"accountNumber": "[REDACTED]", "field": "mailingAddress"},
        field_hashes={"accountNumber": field_hash},
    )
    removed = _event(
        payload={"field": "mailingAddress"}, field_hashes={"accountNumber": field_hash}
    )
    assert compute_content_hash(**before) == compute_content_hash(**redacted)
    assert compute_content_hash(**before) == compute_content_hash(**removed)


def test_content_hash_changes_when_field_hash_changes() -> None:
    payload = {"accountNumber": "123456789"}
    first = _event(payload=payload, field_hashes={"accountNumber": compute_field_hash(SALT, "1")})
    second = _event(payload=payload, field_hashes={"accountNumber": compute_field_hash(SALT, "2")})
    assert compute_content_hash(**first) != compute_content_hash(**second)
