"""Archive audit records older than RETENTION_DAYS. Run with ``make retention``."""

from audit_log.operations.retention import main

if __name__ == "__main__":
    raise SystemExit(main())
