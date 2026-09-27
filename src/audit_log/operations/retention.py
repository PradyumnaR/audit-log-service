"""Retention: archive records older than ``RETENTION_DAYS``.

Operator-only, run with ``make retention`` (``scripts/run_retention.py``). There is
deliberately no API endpoint for it, so callers cannot trigger archiving.
"""

import sys
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.config import retention_days
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import archive_expired


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_retention(engine: Engine, days: int, *, now: Callable[[], datetime] = _utc_now) -> int:
    """Archive records older than ``days`` in ``engine``'s database; return how many."""
    create_schema(engine)
    with Session(engine) as session:
        return archive_expired(session, days, now=now)


def main(engine: Engine | None = None) -> int:
    """Entry point: read ``RETENTION_DAYS`` and archive. Returns the process exit code."""
    try:
        days = retention_days()
    except ValueError as exc:
        print(f"retention: {exc}", file=sys.stderr)
        return 1
    engine = engine if engine is not None else make_engine()
    archived = run_retention(engine, days)
    print(f"retention: archived {archived} record(s) older than {days} day(s)")
    return 0
