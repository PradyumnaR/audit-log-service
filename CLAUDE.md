# Audit Log Service

## Purpose

Tamper-evident, append-only audit log service with hash chain verification.

## Stack

Python 3.13, FastAPI, Pydantic, SQLAlchemy, SQLite, pytest, ruff, mypy, bandit, pip-audit. Managed with uv.

## Commands

- make run / make test / make lint / make typecheck / make security / make check

## Hard constraints

- Audit records are append-only. Never add update or delete endpoints for records.
- Hashing uses SHA-256 over canonically serialized content (see docs/architecture.md).
- Every feature needs unit tests; API features need integration tests.
- No secrets, credentials, or real personal data in code, tests, or fixtures.
- Do not run git commit or git push. The engineer reviews and commits.

## Definition of done

- Acceptance criteria in docs/scenario-\*.md met
- make check passes
- Relevant docs updated

## References

- docs/architecture.md for design decisions
- docs/scenario-a.md, scenario-b.md, scenario-c.md for tasks and acceptance criteria
