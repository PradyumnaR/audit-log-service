"""Engine and schema setup for the audit database."""

from typing import Any

from sqlalchemy import Connection, Engine, create_engine, event

from audit_log.config import database_url
from audit_log.storage.models import Base


def make_engine(url: str | None = None) -> Engine:
    """Create an engine for ``url`` (defaults to ``DATABASE_URL``).

    On SQLite every transaction starts with ``BEGIN IMMEDIATE``, which takes the database
    write lock up front. Concurrent appends therefore run one at a time: each one reads the
    latest hash and inserts its record before the next can start, keeping one chain.
    """
    engine = create_engine(url or database_url())
    if engine.dialect.name == "sqlite":
        _use_immediate_transactions(engine)
    return engine


def _use_immediate_transactions(engine: Engine) -> None:
    # SQLAlchemy recipe: stop pysqlite from issuing its own deferred BEGIN, then emit
    # BEGIN IMMEDIATE ourselves whenever SQLAlchemy starts a transaction.
    @event.listens_for(engine, "connect")
    def _disable_pysqlite_begin(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _begin_immediate(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")


def create_schema(engine: Engine) -> None:
    """Create the ``audit_events`` table and indexes if they do not exist."""
    Base.metadata.create_all(engine)
