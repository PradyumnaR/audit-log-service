"""SQLAlchemy model for the append-only ``audit_events`` table."""

from typing import Any

from sqlalchemy import JSON, Boolean, CheckConstraint, Index, Integer, String, false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

HASH_HEX_LENGTH = 64
TYPE_MAX_LENGTH = 64
ID_MAX_LENGTH = 255
TIMESTAMP_LENGTH = 20  # "YYYY-MM-DDTHH:MM:SSZ"


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    """One record in the hash chain.

    ``id`` is the chain order number: SQLite AUTOINCREMENT guarantees ids are strictly
    increasing and never reused, even after a row is deleted.

    Event content columns are nullable only so retention can clear them on archived rows
    (scenario B); the check constraint requires them on every non-archived row.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "archived OR ("
            "event_type IS NOT NULL AND actor_id IS NOT NULL AND resource_type IS NOT NULL"
            " AND resource_id IS NOT NULL AND payload IS NOT NULL)",
            name="ck_audit_events_content_required",
        ),
        Index("ix_audit_events_actor_id", "actor_id"),
        Index("ix_audit_events_resource", "resource_type", "resource_id"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_timestamp", "timestamp"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str | None] = mapped_column(String(TYPE_MAX_LENGTH))
    actor_id: Mapped[str | None] = mapped_column(String(ID_MAX_LENGTH))
    resource_type: Mapped[str | None] = mapped_column(String(TYPE_MAX_LENGTH))
    resource_id: Mapped[str | None] = mapped_column(String(ID_MAX_LENGTH))
    # none_as_null: store None as SQL NULL (not JSON 'null') so the check constraint applies.
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON(none_as_null=True))
    # Stored as the exact canonical string that is hashed (UTC ISO 8601 with Z); the fixed
    # format also sorts correctly as text for time-range queries.
    timestamp: Mapped[str] = mapped_column(String(TIMESTAMP_LENGTH), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(HASH_HEX_LENGTH), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(HASH_HEX_LENGTH), nullable=False)
    # Not hashed: set by retention after write.
    archived: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # Hashed (via the content hash): {sensitive key: SHA-256(salt + canonical value)}.
    field_hashes: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    # Not hashed: {sensitive key: hex salt}; an entry is removed on redaction.
    field_salts: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
