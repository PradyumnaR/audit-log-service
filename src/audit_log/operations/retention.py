"""Retention: archive records with a timestamp strictly earlier than a cutoff.

Operator-only, run with ``make retention BEFORE=...`` (``scripts/run_retention.py``). There
is deliberately no API endpoint for it, so callers cannot trigger archiving. The cutoff is
required on every run, so a missing setting never archives records by accident.
"""

import argparse
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.domain.hashing import format_timestamp
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import archive_before

# Canonical stored form: ISO 8601 UTC, whole seconds, ``Z`` suffix.
_CUTOFF = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def parse_cutoff(raw: str, *, now: Callable[[], datetime] = _utc_now) -> datetime:
    """Parse ``--before`` (e.g. ``2026-01-01T00:00:00Z``); reject bad formats and the future."""
    if not _CUTOFF.match(raw):
        raise ValueError("must be ISO 8601 UTC with Z, e.g. 2026-01-01T00:00:00Z")
    try:
        cutoff = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"is not a valid date-time: {raw}") from exc
    if cutoff > now():
        raise ValueError(f"must not be in the future: {raw}")
    return cutoff


def run_retention(engine: Engine, before: datetime) -> int:
    """Archive records older than ``before`` in ``engine``'s database; return how many."""
    create_schema(engine)
    with Session(engine) as session:
        return archive_before(session, before)


def main(
    argv: Sequence[str] | None = None,
    engine: Engine | None = None,
    *,
    now: Callable[[], datetime] = _utc_now,
) -> int:
    """Entry point: parse ``--before`` and archive. Returns the process exit code.

    Missing or invalid arguments exit with status 2 (argparse convention).
    """
    parser = argparse.ArgumentParser(
        prog="run_retention", description="Archive audit records older than a cutoff."
    )
    parser.add_argument(
        "--before",
        required=True,
        metavar="TIMESTAMP",
        help="ISO 8601 UTC cutoff with Z; records strictly earlier are archived",
    )
    args = parser.parse_args(argv)
    try:
        before = parse_cutoff(args.before, now=now)
    except ValueError as exc:
        parser.error(f"--before {exc}")
    engine = engine if engine is not None else make_engine()
    archived = run_retention(engine, before)
    print(f"retention: archived {archived} record(s) older than {format_timestamp(before)}")
    return 0
