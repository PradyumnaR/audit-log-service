"""Pydantic request/response models for ``/audit/events``.

Validation is strict because an append-only log cannot fix bad data later: missing fields,
wrong types, bad formats, unknown fields, and oversized payloads are rejected. The server
assigns the timestamp, so a caller-supplied ``timestamp`` is rejected as an unknown field.
Query parameters are validated the same way, so a typo'd filter is rejected rather than
silently ignored.
"""

import re
from datetime import datetime, timedelta
from typing import Annotated, Any, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel

from audit_log.domain.hashing import canonical_json, format_timestamp
from audit_log.storage.models import ID_MAX_LENGTH, TYPE_MAX_LENGTH, AuditEvent
from audit_log.storage.repository import EventFilter, EventPage, NewEvent

# Upper bound on the canonical JSON of ``payload``, in UTF-8 bytes.
MAX_PAYLOAD_BYTES = 16 * 1024

# UPPER_SNAKE_CASE: an uppercase letter, then uppercase letters/digits, single underscores
# between words, e.g. USER_LOGIN, RECORD_UPDATED.
UPPER_SNAKE_CASE = r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$"
# Non-empty, no leading/trailing whitespace, no line breaks.
TRIMMED_TEXT = r"^\S(.*\S)?$"

TypeName = Annotated[str, Field(max_length=TYPE_MAX_LENGTH, pattern=UPPER_SNAKE_CASE)]
Identifier = Annotated[str, Field(min_length=1, max_length=ID_MAX_LENGTH, pattern=TRIMMED_TEXT)]

DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# Shown in place of a sensitive value whose raw value and salt were removed by redaction.
REDACTED = "[REDACTED]"

# ISO 8601 date-time with an explicit offset (Z or +HH:MM), optional fractional seconds.
# Checked before parsing so Pydantic's other accepted forms (e.g. Unix epochs) are refused.
_ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")


def _require_iso_datetime(value: Any) -> Any:
    if not isinstance(value, str) or not _ISO_DATETIME.match(value):
        raise ValueError("must be an ISO 8601 date-time with Z or an offset")
    return value


QueryDatetime = Annotated[AwareDatetime, BeforeValidator(_require_iso_datetime)]
# Record id of the last item on the previous page.
Cursor = Annotated[str, Field(pattern=r"^[1-9][0-9]{0,18}$")]


def _stored_bound(moment: datetime) -> str:
    """Convert a query bound to the stored second-precision format.

    Stored timestamps are whole seconds, so rounding a fractional bound up keeps both
    ``timestamp >= from`` and ``timestamp < to`` exact.
    """
    if moment.microsecond:
        moment = moment.replace(microsecond=0) + timedelta(seconds=1)
    return format_timestamp(moment)


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel)


class EventCreate(_CamelModel):
    """Body of ``POST /audit/events``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_type: TypeName
    actor_id: Identifier
    resource_type: TypeName
    resource_id: Identifier
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def _payload_hashable_and_bounded(cls, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(canonical_json(payload).encode("utf-8"))
        except ValueError as exc:  # NaN/Infinity are not valid canonical JSON
            raise ValueError("payload must not contain NaN or Infinity") from exc
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload must be at most {MAX_PAYLOAD_BYTES} bytes as JSON")
        return payload

    def to_new_event(self) -> NewEvent:
        return NewEvent(
            event_type=self.event_type,
            actor_id=self.actor_id,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            payload=self.payload,
        )


class EventCreated(_CamelModel):
    """Response of ``POST /audit/events``: the stored event with its server timestamp."""

    model_config = ConfigDict(validate_by_name=True)

    id: int
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: dict[str, Any]
    timestamp: str


class EventQuery(_CamelModel):
    """Query parameters of ``GET /audit/events``."""

    model_config = ConfigDict(extra="forbid")

    event_type: TypeName | None = None
    actor_id: Identifier | None = None
    resource_type: TypeName | None = None
    resource_id: Identifier | None = None
    from_: QueryDatetime | None = Field(default=None, alias="from")
    to: QueryDatetime | None = None
    limit: int = Field(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)
    cursor: Cursor | None = None

    @model_validator(mode="after")
    def _check_combinations(self) -> Self:
        # IDs may repeat across resource types, so an ID alone is ambiguous.
        if self.resource_id is not None and self.resource_type is None:
            raise ValueError("resourceId requires resourceType")
        if self.from_ is not None and self.to is not None and self.from_ >= self.to:
            raise ValueError("from must be earlier than to")
        return self

    def to_filter(self) -> EventFilter:
        return EventFilter(
            event_type=self.event_type,
            actor_id=self.actor_id,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            from_timestamp=_stored_bound(self.from_) if self.from_ is not None else None,
            to_timestamp=_stored_bound(self.to) if self.to is not None else None,
        )

    @property
    def after_id(self) -> int | None:
        return int(self.cursor) if self.cursor is not None else None


class EventRecord(EventCreated):
    """A stored event as returned by queries, with its chain hashes."""

    content_hash: str
    previous_hash: str

    @classmethod
    def from_record(cls, record: AuditEvent) -> Self:
        """Build the response for a non-archived record; redacted values show ``REDACTED``."""
        if (
            record.event_type is None
            or record.actor_id is None
            or record.resource_type is None
            or record.resource_id is None
            or record.payload is None
        ):
            raise ValueError(f"record {record.id} has no content (archived)")
        payload = dict(record.payload)
        for key in record.field_hashes:
            if key not in record.field_salts:
                payload[key] = REDACTED
        return cls(
            id=record.id,
            event_type=record.event_type,
            actor_id=record.actor_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            payload=payload,
            timestamp=record.timestamp,
            content_hash=record.content_hash,
            previous_hash=record.previous_hash,
        )


class EventList(_CamelModel):
    """Response of ``GET /audit/events``. ``nextCursor`` is ``null`` on the last page."""

    model_config = ConfigDict(validate_by_name=True)

    items: list[EventRecord]
    next_cursor: str | None

    @classmethod
    def from_page(cls, page: EventPage) -> Self:
        return cls(
            items=[EventRecord.from_record(record) for record in page.records],
            next_cursor=str(page.next_after_id) if page.next_after_id is not None else None,
        )
