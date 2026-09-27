"""Archive audit records older than a cutoff. Run with ``make retention BEFORE=...``."""

from audit_log.operations.retention import main

if __name__ == "__main__":
    raise SystemExit(main())
