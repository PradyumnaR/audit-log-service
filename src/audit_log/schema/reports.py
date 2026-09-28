"""Pydantic models for ``GET /audit/reports/account-access`` (scenario C).

An account access event is a ``resourceType`` ``ACCOUNT`` event whose ``eventType`` is one
of ``ACCOUNT_ACCESS_EVENT_TYPES``. The report reuses the ``GET /audit/events`` filter,
pagination, time-range rules and ``EventList`` response; only the fixed resource type and
event types and the required ``from``/``to`` differ.
"""

from typing import Self

from pydantic import ConfigDict, Field, model_validator

from audit_log.schema.events import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Cursor,
    Identifier,
    QueryDatetime,
    _CamelModel,
    _stored_bound,
)
from audit_log.storage.repository import EventFilter

ACCOUNT_RESOURCE_TYPE = "ACCOUNT"
ACCOUNT_ACCESS_EVENT_TYPES = frozenset({"ACCOUNT_VIEWED", "ACCOUNT_UPDATED", "ACCOUNT_EXPORTED"})


class AccountAccessQuery(_CamelModel):
    """Query parameters: required ``from``/``to``, optional ``resourceId`` and ``actorId``."""

    model_config = ConfigDict(extra="forbid")

    from_: QueryDatetime = Field(alias="from")
    to: QueryDatetime
    resource_id: Identifier | None = None
    actor_id: Identifier | None = None
    limit: int = Field(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)
    cursor: Cursor | None = None

    @model_validator(mode="after")
    def _check_range(self) -> Self:
        if self.from_ >= self.to:
            raise ValueError("from must be earlier than to")
        return self

    def to_filter(self) -> EventFilter:
        return EventFilter(
            event_types=ACCOUNT_ACCESS_EVENT_TYPES,
            actor_id=self.actor_id,
            resource_type=ACCOUNT_RESOURCE_TYPE,
            resource_id=self.resource_id,
            from_timestamp=_stored_bound(self.from_),
            to_timestamp=_stored_bound(self.to),
        )

    @property
    def after_id(self) -> int | None:
        return int(self.cursor) if self.cursor is not None else None
