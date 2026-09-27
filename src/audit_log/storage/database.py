"""Engine and schema setup for the audit database."""

from sqlalchemy import Engine, create_engine

from audit_log.config import database_url
from audit_log.storage.models import Base


def make_engine(url: str | None = None) -> Engine:
    """Create an engine for ``url`` (defaults to ``DATABASE_URL``)."""
    return create_engine(url or database_url())


def create_schema(engine: Engine) -> None:
    """Create the ``audit_events`` table and indexes if they do not exist."""
    Base.metadata.create_all(engine)
