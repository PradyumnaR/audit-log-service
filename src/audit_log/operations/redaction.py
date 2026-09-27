"""Redaction: remove the raw value and salt of one sensitive field of one record.

Operator-only, run with ``make redact ID=... FIELD=...`` (``scripts/redact.py``). There is
deliberately no API endpoint for it, so the public API stays write-and-read only. No stored
hash changes, so the chain still verifies (see ``redact_field``).
"""

import argparse
import sys
from collections.abc import Sequence

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import RedactionRefusedError, redact_field


def _record_id(raw: str) -> int:
    if not raw.isascii() or not raw.isdigit() or int(raw) < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer: {raw!r}")
    return int(raw)


def run_redaction(engine: Engine, record_id: int, field: str) -> None:
    """Redact ``field`` of record ``record_id`` in ``engine``'s database.

    Uses the ``SENSITIVE_FIELDS`` config; raises ``RedactionRefusedError`` if refused.
    """
    create_schema(engine)
    with Session(engine) as session:
        redact_field(session, record_id, field)


def main(argv: Sequence[str] | None = None, engine: Engine | None = None) -> int:
    """Entry point: parse ``--id`` and ``--field`` and redact. Returns the process exit code.

    Missing or invalid arguments exit with status 2 (argparse convention); a refused
    redaction exits with status 1 and changes nothing.
    """
    parser = argparse.ArgumentParser(
        prog="redact", description="Redact one sensitive payload field of one audit record."
    )
    parser.add_argument("--id", required=True, type=_record_id, help="record id")
    parser.add_argument("--field", required=True, help="top-level payload key in SENSITIVE_FIELDS")
    args = parser.parse_args(argv)
    engine = engine if engine is not None else make_engine()
    try:
        run_redaction(engine, args.id, args.field)
    except RedactionRefusedError as exc:
        print(f"redact: refused: {exc}", file=sys.stderr)
        return 1
    print(f"redact: redacted field {args.field!r} of record {args.id}")
    return 0
