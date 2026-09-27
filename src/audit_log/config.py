"""Runtime configuration read from environment variables."""

import os

DEFAULT_DATABASE_URL = "sqlite:///./audit_log.db"


def database_url() -> str:
    """SQLAlchemy URL for the audit database (``DATABASE_URL``)."""
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def sensitive_fields() -> frozenset[str]:
    """Top-level payload keys protected by salted field hashes (``SENSITIVE_FIELDS``).

    Comma-separated, e.g. ``SENSITIVE_FIELDS=accountNumber,taxId``. Empty by default.
    """
    raw = os.environ.get("SENSITIVE_FIELDS", "")
    return frozenset(field.strip() for field in raw.split(",") if field.strip())


def retention_days() -> int:
    """Age in days after which records are archived (``RETENTION_DAYS``).

    Required by the retention script; must be a positive integer. There is no default so a
    missing setting never archives records by accident.
    """
    raw = os.environ.get("RETENTION_DAYS", "").strip()
    if not raw:
        raise ValueError("RETENTION_DAYS is not set")
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError("RETENTION_DAYS must be an integer") from exc
    if days < 1:
        raise ValueError("RETENTION_DAYS must be at least 1")
    return days
