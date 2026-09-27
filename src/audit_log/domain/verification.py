"""Hash chain verification.

Walks records in chain (id) order and reports the first inconsistency. Like
``audit_log.domain.hashing`` this module uses only the standard library: records are read
through the ``ChainRecord`` protocol, which the storage model satisfies, so no database
types leak into the domain layer.

Checks per record, in order (the first failing check is reported):

``INVALID_ARCHIVE``
    An archived record follows a non-archived one. Retention archives oldest-first, so
    archived records must form one continuous block starting at the first record.
``BROKEN_LINK``
    ``previousHash`` is not the preceding record's ``contentHash`` (or the genesis hash for
    the first record), e.g. a record was deleted or reordered.
``CONTENT_HASH_MISMATCH``
    Non-archived records only (archived content is cleared, so only the link is checked):
    the recomputed content hash differs from the stored one, or a sensitive value that
    still has its salt no longer matches its field hash. Redacted fields (value or salt
    removed) skip the field check; their field hash is still covered by the content hash.

Deleting the most recent records cannot be detected from the chain alone: nothing after
them refers to their hashes.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from audit_log.domain.hashing import GENESIS_HASH, compute_content_hash, field_hash_matches


class ViolationType(StrEnum):
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    BROKEN_LINK = "BROKEN_LINK"
    INVALID_ARCHIVE = "INVALID_ARCHIVE"


class ChainRecord(Protocol):
    """The stored fields verification reads from each record."""

    @property
    def id(self) -> int: ...
    @property
    def event_type(self) -> str | None: ...
    @property
    def actor_id(self) -> str | None: ...
    @property
    def resource_type(self) -> str | None: ...
    @property
    def resource_id(self) -> str | None: ...
    @property
    def payload(self) -> Mapping[str, Any] | None: ...
    @property
    def timestamp(self) -> str: ...
    @property
    def content_hash(self) -> str: ...
    @property
    def previous_hash(self) -> str: ...
    @property
    def archived(self) -> bool: ...
    @property
    def field_hashes(self) -> Mapping[str, str]: ...
    @property
    def field_salts(self) -> Mapping[str, str]: ...


@dataclass(frozen=True)
class Violation:
    record_id: int
    violation_type: ViolationType
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """``records_checked`` counts records up to and including the first broken one."""

    records_checked: int
    violation: Violation | None = None

    @property
    def intact(self) -> bool:
        return self.violation is None


def verify_chain(records: Iterable[ChainRecord]) -> VerificationResult:
    """Verify ``records`` (in id order) and stop at the first violation."""
    expected_previous = GENESIS_HASH
    seen_live = False
    checked = 0
    for record in records:
        checked += 1
        violation = _check_record(record, expected_previous, seen_live)
        if violation is not None:
            return VerificationResult(records_checked=checked, violation=violation)
        expected_previous = record.content_hash
        seen_live = seen_live or not record.archived
    return VerificationResult(records_checked=checked)


def _check_record(record: ChainRecord, expected_previous: str, seen_live: bool) -> Violation | None:
    if record.archived and seen_live:
        return Violation(
            record.id,
            ViolationType.INVALID_ARCHIVE,
            "Archived record follows a non-archived record",
        )
    if record.previous_hash != expected_previous:
        if expected_previous == GENESIS_HASH:
            detail = "previousHash of the first record does not match the genesis hash"
        else:
            detail = "previousHash does not match the preceding record's contentHash"
        return Violation(record.id, ViolationType.BROKEN_LINK, detail)
    if record.archived:
        return None
    problem = _content_problem(record)
    if problem is not None:
        return Violation(record.id, ViolationType.CONTENT_HASH_MISMATCH, problem)
    return None


def _content_problem(record: ChainRecord) -> str | None:
    if (
        record.event_type is None
        or record.actor_id is None
        or record.resource_type is None
        or record.resource_id is None
        or record.payload is None
    ):
        return "Non-archived record is missing event content"
    recomputed = compute_content_hash(
        event_type=record.event_type,
        actor_id=record.actor_id,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        timestamp=record.timestamp,
        payload=record.payload,
        field_hashes=record.field_hashes,
        previous_hash=record.previous_hash,
    )
    if recomputed != record.content_hash:
        return "Stored contentHash does not match recomputed hash"
    for key in sorted(record.field_hashes):
        if key not in record.payload or key not in record.field_salts:
            continue  # redacted
        if not field_hash_matches(
            record.field_salts[key], record.payload[key], record.field_hashes[key]
        ):
            return f"Value of sensitive field {key!r} does not match its field hash"
    return None
