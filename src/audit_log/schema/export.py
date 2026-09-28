"""Pydantic models for ``GET /audit/export``: an offline-verifiable bundle.

The bundle carries everything needed to recompute every hash without the service: each
record's hashed fields, its ``fieldHashes``, the salts of unredacted sensitive fields, and a
``bundleHash`` over the content hashes in id order (see ``audit_log.domain.hashing``).
``scripts/verify_bundle.py`` checks it.
"""

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Self

from pydantic import ConfigDict, model_validator

from audit_log.domain.hashing import (
    HASH_ALGORITHM,
    SERIALIZATION,
    compute_bundle_hash,
    format_timestamp,
)
from audit_log.schema.events import EventRecord, Identifier, TypeName, _CamelModel
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import EventFilter


class ExportQuery(_CamelModel):
    """Query parameters: ``actorId``, or ``resourceType`` + ``resourceId``."""

    model_config = ConfigDict(extra="forbid")

    actor_id: Identifier | None = None
    resource_type: TypeName | None = None
    resource_id: Identifier | None = None

    @model_validator(mode="after")
    def _one_subject(self) -> Self:
        # IDs may repeat across resource types, so an ID alone is ambiguous.
        if self.resource_id is not None and self.resource_type is None:
            raise ValueError("resourceId requires resourceType")
        if self.resource_type is not None and self.resource_id is None:
            raise ValueError("resourceType requires resourceId for export")
        if self.actor_id is not None and self.resource_type is not None:
            raise ValueError("export by actorId or by resourceType + resourceId, not both")
        if self.actor_id is None and self.resource_type is None:
            raise ValueError("export requires actorId, or resourceType with resourceId")
        return self

    def to_filter(self) -> EventFilter:
        return EventFilter(
            actor_id=self.actor_id,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
        )

    def described(self) -> dict[str, str]:
        """The filter as given, with camelCase keys, for the bundle metadata."""
        return self.model_dump(by_alias=True, exclude_none=True)


class ExportRecord(EventRecord):
    """A record as exported: the response fields plus field hashes and remaining salts."""

    field_hashes: dict[str, str]
    field_salts: dict[str, str]

    @classmethod
    def from_record(cls, record: AuditEvent) -> Self:
        """Build from a non-archived record; salts of redacted fields are left out."""
        base = EventRecord.from_record(record)
        payload = record.payload or {}
        return cls(
            **base.model_dump(),
            field_hashes=dict(record.field_hashes),
            field_salts={key: salt for key, salt in record.field_salts.items() if key in payload},
        )


class ExportMetadata(_CamelModel):
    model_config = ConfigDict(validate_by_name=True)

    exported_at: str
    filter: dict[str, str]
    hash_algorithm: str
    serialization: str
    sensitive_fields: list[str]
    record_count: int


class ExportBundle(_CamelModel):
    """Response of ``GET /audit/export``."""

    model_config = ConfigDict(validate_by_name=True)

    metadata: ExportMetadata
    records: list[ExportRecord]
    bundle_hash: str

    @classmethod
    def build(
        cls,
        query: ExportQuery,
        records: Sequence[AuditEvent],
        *,
        sensitive_fields: Iterable[str],
        exported_at: datetime,
    ) -> Self:
        return cls(
            metadata=ExportMetadata(
                exported_at=format_timestamp(exported_at),
                filter=query.described(),
                hash_algorithm=HASH_ALGORITHM,
                serialization=SERIALIZATION,
                sensitive_fields=sorted(sensitive_fields),
                record_count=len(records),
            ),
            records=[ExportRecord.from_record(record) for record in records],
            bundle_hash=compute_bundle_hash(record.content_hash for record in records),
        )
