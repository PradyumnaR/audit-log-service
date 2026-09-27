"""Persistence operations for the append-only ``audit_events`` table."""

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, func, select, update
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


@dataclass(frozen=True)
class EventFilter:
    """Query filters; ``None`` means "any". Timestamps are canonical UTC strings."""

    event_type: str | None = None
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    from_timestamp: str | None = None  # inclusive
    to_timestamp: str | None = None  # exclusive


@dataclass(frozen=True)
class EventPage:
    """One page of query results and the id to continue after, if more remain."""

    records: list[AuditEvent]
    next_after_id: int | None


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


def query_events(
    session: Session, event_filter: EventFilter, *, limit: int, after_id: int | None = None
) -> EventPage:
    """Return up to ``limit`` non-archived records matching ``event_filter``, in id order.

    Pagination is keyset-based on ``id``: pass the previous page's ``next_after_id`` as
    ``after_id`` to continue. Archived records are excluded because their content is gone.
    Timestamps are fixed-format strings, so text comparison matches time order.
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")
    statement = select(AuditEvent).where(AuditEvent.archived.is_(False))
    if event_filter.event_type is not None:
        statement = statement.where(AuditEvent.event_type == event_filter.event_type)
    if event_filter.actor_id is not None:
        statement = statement.where(AuditEvent.actor_id == event_filter.actor_id)
    if event_filter.resource_type is not None:
        statement = statement.where(AuditEvent.resource_type == event_filter.resource_type)
    if event_filter.resource_id is not None:
        statement = statement.where(AuditEvent.resource_id == event_filter.resource_id)
    if event_filter.from_timestamp is not None:
        statement = statement.where(AuditEvent.timestamp >= event_filter.from_timestamp)
    if event_filter.to_timestamp is not None:
        statement = statement.where(AuditEvent.timestamp < event_filter.to_timestamp)
    if after_id is not None:
        statement = statement.where(AuditEvent.id > after_id)
    # Fetch one extra row to learn whether another page exists.
    records = list(session.scalars(statement.order_by(AuditEvent.id).limit(limit + 1)))
    if len(records) > limit:
        records = records[:limit]
        return EventPage(records=records, next_after_id=records[-1].id)
    return EventPage(records=records, next_after_id=None)


CHAIN_BATCH_SIZE = 500


def iter_chain(session: Session) -> Iterator[AuditEvent]:
    """Yield every record, archived or not, in chain (id) order.

    Rows are fetched in batches so verification does not load the whole table at once. On
    SQLite the read runs under the write lock (see ``make_engine``), so appends wait and the
    walk sees one consistent chain.
    """
    statement = (
        select(AuditEvent).order_by(AuditEvent.id).execution_options(yield_per=CHAIN_BATCH_SIZE)
    )
    yield from session.scalars(statement)


def archive_before(session: Session, before: datetime) -> int:
    """Archive every record with a timestamp strictly earlier than ``before``; return how many.

    Archiving sets ``archived`` and clears the event content, field hashes and salts,
    keeping only ``id``, ``timestamp``, ``contentHash`` and ``previousHash`` so the chain
    stays linked. None of the kept values change, so no stored hash changes.

    Records are archived as an id prefix: everything up to the newest record older than the
    cutoff. Timestamps never decrease in id order (see ``append_event``), so this is the
    same set as "older than the cutoff", and archived records always form one continuous
    block from the first record, as verification requires. On SQLite the transaction holds
    the write lock (see ``make_engine``), so appends wait until it commits.
    """
    if before.microsecond:
        raise ValueError("before must be a whole second")
    cutoff = format_timestamp(before)
    last_expired_id = session.scalar(
        select(func.max(AuditEvent.id)).where(AuditEvent.timestamp < cutoff)
    )
    if last_expired_id is None:
        session.commit()
        return 0
    statement = (
        update(AuditEvent)
        .where(AuditEvent.id <= last_expired_id, AuditEvent.archived.is_(False))
        .values(
            archived=True,
            event_type=None,
            actor_id=None,
            resource_type=None,
            resource_id=None,
            payload=None,
            field_hashes={},
            field_salts={},
        )
    )
    # DML statements return a CursorResult, which carries the matched row count.
    result = cast(CursorResult[Any], session.execute(statement))
    session.commit()
    return result.rowcount
