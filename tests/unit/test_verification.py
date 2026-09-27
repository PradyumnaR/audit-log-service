"""Unit tests for hash chain verification in the domain layer."""

from dataclasses import dataclass, field, replace
from typing import Any

import pytest

from audit_log.domain.hashing import (
    GENESIS_HASH,
    compute_content_hash,
    compute_field_hash,
    generate_salt,
)
from audit_log.domain.verification import (
    VerificationResult,
    Violation,
    ViolationType,
    verify_chain,
)


@dataclass(frozen=True)
class Record:
    """Plain stand-in for a stored record; satisfies ``ChainRecord``."""

    id: int
    content_hash: str
    previous_hash: str
    event_type: str | None = "RECORD_UPDATED"
    actor_id: str | None = "user-1042"
    resource_type: str | None = "ACCOUNT"
    resource_id: str | None = "acct-88731"
    payload: dict[str, Any] | None = field(default_factory=lambda: {"field": "mailingAddress"})
    timestamp: str = "2026-09-24T14:32:10Z"
    archived: bool = False
    field_hashes: dict[str, str] = field(default_factory=dict)
    field_salts: dict[str, str] = field(default_factory=dict)


def _hash_of(record: Record) -> str:
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


def _chain(count: int, *, sensitive: dict[str, Any] | None = None) -> list[Record]:
    """Build a valid chain; ``sensitive`` values are salted and field-hashed in each record."""
    records: list[Record] = []
    previous = GENESIS_HASH
    for i in range(1, count + 1):
        payload: dict[str, Any] = {"field": "mailingAddress", "n": i}
        salts: dict[str, str] = {}
        hashes: dict[str, str] = {}
        for key, value in (sensitive or {}).items():
            payload[key] = value
            salts[key] = generate_salt()
            hashes[key] = compute_field_hash(salts[key], value)
        draft = Record(
            id=i,
            content_hash="",
            previous_hash=previous,
            payload=payload,
            field_hashes=hashes,
            field_salts=salts,
        )
        record = replace(draft, content_hash=_hash_of(draft))
        records.append(record)
        previous = record.content_hash
    return records


def _archived(record: Record) -> Record:
    return replace(
        record,
        archived=True,
        event_type=None,
        actor_id=None,
        resource_type=None,
        resource_id=None,
        payload=None,
    )


def _violation(result: VerificationResult) -> tuple[int, ViolationType]:
    assert result.violation is not None
    return result.violation.record_id, result.violation.violation_type


def test_empty_chain_is_intact() -> None:
    result = verify_chain([])
    assert result == VerificationResult(records_checked=0)
    assert result.intact


def test_valid_chain_is_intact() -> None:
    result = verify_chain(_chain(5))
    assert result.intact
    assert result.records_checked == 5
    assert result.violation is None


def test_edited_content_is_content_hash_mismatch() -> None:
    records = _chain(4)
    records[2] = replace(records[2], actor_id="user-9999")

    result = verify_chain(records)

    assert not result.intact
    assert result.records_checked == 3
    assert result.violation == Violation(
        3,
        ViolationType.CONTENT_HASH_MISMATCH,
        "Stored contentHash does not match recomputed hash",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"event_type": "USER_LOGIN"},
        {"resource_type": "USER"},
        {"resource_id": "acct-1"},
        {"timestamp": "2026-09-24T14:32:11Z"},
        {"payload": {"field": "other"}},
        {"field_hashes": {"accountNumber": "0" * 64}},
        {"content_hash": "0" * 64},
    ],
)
def test_any_hashed_field_edit_is_detected(change: dict[str, Any]) -> None:
    records = _chain(3)
    records[1] = replace(records[1], **change)
    assert _violation(verify_chain(records)) == (2, ViolationType.CONTENT_HASH_MISMATCH)


def test_rehashed_edit_breaks_the_next_link() -> None:
    # A forger who also recomputes the edited record's hash breaks the following link.
    records = _chain(4)
    forged = replace(records[1], actor_id="user-9999")
    records[1] = replace(forged, content_hash=_hash_of(forged))

    result = verify_chain(records)

    assert _violation(result) == (3, ViolationType.BROKEN_LINK)
    assert result.violation is not None
    assert "preceding record" in result.violation.detail


def test_deleted_middle_record_is_broken_link() -> None:
    records = _chain(4)
    del records[1]
    assert _violation(verify_chain(records)) == (3, ViolationType.BROKEN_LINK)


def test_deleted_first_record_is_broken_link_to_genesis() -> None:
    records = _chain(3)[1:]
    result = verify_chain(records)
    assert _violation(result) == (2, ViolationType.BROKEN_LINK)
    assert result.violation is not None
    assert "genesis" in result.violation.detail


def test_reordered_records_are_broken_link() -> None:
    records = _chain(3)
    records[1], records[2] = records[2], records[1]
    assert _violation(verify_chain(records)) == (3, ViolationType.BROKEN_LINK)


def test_deleted_last_record_is_not_detectable() -> None:
    # Documented limit: nothing after the newest record refers to its hash.
    assert verify_chain(_chain(3)[:-1]).intact


def test_reports_only_the_first_violation() -> None:
    records = _chain(5)
    records[1] = replace(records[1], actor_id="user-9999")
    records[3] = replace(records[3], previous_hash="0" * 64)
    result = verify_chain(records)
    assert _violation(result) == (2, ViolationType.CONTENT_HASH_MISMATCH)
    assert result.records_checked == 2


def test_stops_reading_at_first_violation() -> None:
    records = _chain(3)
    records[0] = replace(records[0], actor_id="user-9999")
    consumed: list[int] = []

    def stream() -> Any:
        for record in records:
            consumed.append(record.id)
            yield record

    verify_chain(stream())
    assert consumed == [1]


def test_non_archived_record_missing_content_is_mismatch() -> None:
    records = _chain(2)
    records[1] = replace(records[1], payload=None)
    result = verify_chain(records)
    assert _violation(result) == (2, ViolationType.CONTENT_HASH_MISMATCH)
    assert result.violation is not None
    assert "missing" in result.violation.detail


def test_archived_prefix_is_intact() -> None:
    records = _chain(4)
    records[0] = _archived(records[0])
    records[1] = _archived(records[1])
    assert verify_chain(records) == VerificationResult(records_checked=4)


def test_fully_archived_chain_is_intact() -> None:
    assert verify_chain([_archived(record) for record in _chain(3)]).intact


def test_archived_record_link_is_still_checked() -> None:
    records = _chain(3)
    records[0] = _archived(records[0])
    records[1] = replace(_archived(records[1]), previous_hash="0" * 64)
    assert _violation(verify_chain(records)) == (2, ViolationType.BROKEN_LINK)


def test_archived_after_live_record_is_invalid_archive() -> None:
    records = _chain(4)
    records[0] = _archived(records[0])
    records[2] = _archived(records[2])
    result = verify_chain(records)
    assert _violation(result) == (3, ViolationType.INVALID_ARCHIVE)
    assert result.records_checked == 3


def test_intact_sensitive_values_match_field_hashes() -> None:
    assert verify_chain(_chain(3, sensitive={"accountNumber": "0000-TEST"})).intact


def test_edited_sensitive_value_is_mismatch() -> None:
    # The content hash excludes raw sensitive values, so only the field hash catches this.
    records = _chain(3, sensitive={"accountNumber": "0000-TEST"})
    payload = {**(records[1].payload or {}), "accountNumber": "1111-TEST"}
    records[1] = replace(records[1], payload=payload)

    result = verify_chain(records)

    assert _violation(result) == (2, ViolationType.CONTENT_HASH_MISMATCH)
    assert result.violation is not None
    assert "accountNumber" in result.violation.detail


@pytest.mark.parametrize("salt", ["not-hex", "ab" * 16, "00" * 32])
def test_edited_salt_is_mismatch(salt: str) -> None:
    records = _chain(2, sensitive={"accountNumber": "0000-TEST"})
    records[0] = replace(records[0], field_salts={"accountNumber": salt})
    assert _violation(verify_chain(records)) == (1, ViolationType.CONTENT_HASH_MISMATCH)


def test_redacted_field_skips_field_check() -> None:
    records = _chain(3, sensitive={"accountNumber": "0000-TEST"})
    payload = {k: v for k, v in (records[1].payload or {}).items() if k != "accountNumber"}
    records[1] = replace(records[1], payload=payload, field_salts={})
    assert verify_chain(records).intact


def test_value_without_salt_is_treated_as_redacted() -> None:
    records = _chain(2, sensitive={"accountNumber": "0000-TEST"})
    records[0] = replace(records[0], field_salts={})
    assert verify_chain(records).intact
