"""Pydantic request/response models for ``/audit/events``.

Validation is strict because an append-only log cannot fix bad data later: missing fields,
wrong types, bad formats, unknown fields, and oversized payloads are rejected. The server
assigns the timestamp, so a caller-supplied ``timestamp`` is rejected as an unknown field.
"""

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel

from audit_log.domain.hashing import canonical_json
from audit_log.storage.models import ID_MAX_LENGTH, TYPE_MAX_LENGTH
from audit_log.storage.repository import NewEvent

# Upper bound on the canonical JSON of ``payload``, in UTF-8 bytes.
MAX_PAYLOAD_BYTES = 16 * 1024

# UPPER_SNAKE_CASE: an uppercase letter, then uppercase letters/digits, single underscores
# between words, e.g. USER_LOGIN, RECORD_UPDATED.
UPPER_SNAKE_CASE = r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$"
# Non-empty, no leading/trailing whitespace, no line breaks.
TRIMMED_TEXT = r"^\S(.*\S)?$"

TypeName = Annotated[str, Field(max_length=TYPE_MAX_LENGTH, pattern=UPPER_SNAKE_CASE)]
Identifier = Annotated[str, Field(min_length=1, max_length=ID_MAX_LENGTH, pattern=TRIMMED_TEXT)]


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
