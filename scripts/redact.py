"""Redact a sensitive payload field of one record. Run with ``make redact ID=... FIELD=...``."""

from audit_log.operations.redaction import main

if __name__ == "__main__":
    raise SystemExit(main())
