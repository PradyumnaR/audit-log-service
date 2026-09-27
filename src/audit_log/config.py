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
