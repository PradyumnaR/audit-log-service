"""Persistence operations for the append-only ``audit_events`` table."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from audit_log.config import sensitive_fields as configured_sensitive_fields
from audit_log.domain.hashing import (
    GENESIS_HASH,
    compute_content_hash,
    format_timestamp,
    protect_sensitive_fields,
)
from audit_log.storage.models import AuditEvent


@dataclass(frozen=True)
class NewEvent:
    """Caller-supplied event content. The server assigns the timestamp and hashes."""

    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: Mapping[str, Any]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def latest_hash(session: Session) -> str:
    """Return the content hash of the last record, or the genesis hash if there is none."""
    last = session.scalar(select(AuditEvent.content_hash).order_by(AuditEvent.id.desc()).limit(1))
    return last if last is not None else GENESIS_HASH


def append_event(
    session: Session,
    new_event: NewEvent,
    *,
    sensitive_fields: Iterable[str] | None = None,
    now: Callable[[], datetime] = _utc_now,
) -> AuditEvent:
    """Append ``new_event`` to the chain and commit.

    The read of the previous hash, the timestamp, and the insert all happen inside one
    transaction. On SQLite that transaction holds the write lock from its first statement
    (see ``make_engine``), so parallel appends are queued and each links to the record
    committed just before it. Taking the timestamp under the lock keeps timestamps in id
    order.

    ``sensitive_fields`` defaults to the ``SENSITIVE_FIELDS`` config.
    """
    if sensitive_fields is None:
        sensitive_fields = configured_sensitive_fields()
    payload = dict(new_event.payload)
    protected = protect_sensitive_fields(payload, sensitive_fields)

    previous_hash = latest_hash(session)
    timestamp = format_timestamp(now())
    record = AuditEvent(
        event_type=new_event.event_type,
        actor_id=new_event.actor_id,
        resource_type=new_event.resource_type,
        resource_id=new_event.resource_id,
        payload=payload,
        timestamp=timestamp,
        field_hashes=protected.field_hashes,
        field_salts=protected.field_salts,
        previous_hash=previous_hash,
        content_hash=compute_content_hash(
            event_type=new_event.event_type,
            actor_id=new_event.actor_id,
            resource_type=new_event.resource_type,
            resource_id=new_event.resource_id,
            timestamp=timestamp,
            payload=payload,
            field_hashes=protected.field_hashes,
            previous_hash=previous_hash,
        ),
    )
    session.add(record)
    session.commit()
    return record
