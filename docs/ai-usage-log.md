## #1 — Scaffold project and quality gates (2026-09-24)

- **Category:** Implementation
- **Prompt:** Scaffold the Python 3.13 project with uv and pyproject.toml (FastAPI, SQLAlchemy, Pydantic, pytest, pytest-cov, ruff, mypy, bandit, pip-audit), with the src/audit_log/{api,domain,storage,schema}, tests/{unit,integration}, and scripts/ layout and no application logic. Add a Makefile with install, run, test, lint, typecheck, security, and check targets so that `make check` passes, plus a .gitignore covering Python, .env, and SQLite files.
- **Decision:** Accepted
- **Rationale:** Reviewed pyproject.toml and Makefile line by line; Structure matches as planned layout.
- **Commit:** 641b0d8

## #2 — Draft: Architecture.md file (2026-09-26)

- **Category:** Analysis/Design
- **Prompt:** Draft docs/architecture.md as a short, simple description of how the system works, using only decisions from docs/scenario-a.md and CLAUDE.md. Use exactly two sections, Summary and Architecture, where Architecture has a two-column table (Scenarios, Summary) with a scenario-a row that summarizes its decisions in 5–7 bullets without repeating the API examples.
- **Decision:** Accepted
- **Rationale:** Reviewd scenario-a.md file decisions updated in architecture.md file
- **Commit:** 41c1b9f

## #3 — Scenario B requirement analysis and design (2026-09-26)

- **Category:** Analysis/Design
- **Prompt:** Claude (chat): explained retention, redaction, and export options and trade-offs for scenario-b.md; drafted decision rows, tasks, and limitations.
- **Decision:** Modified — Human sign-off: redaction scheme reviewed and approved.
- **Rationale:**
  - Retention: rejected my first idea of an API with the window in the request, since any caller could archive everything; chose a script with RETENTION_DAYS in config. Dropped the suggested archivedAt column as unnecessary.
  - Noticed archived records always form a continuous block from the start (server timestamps, serialized writes); used this for the INVALID_ARCHIVE check instead of a timestamp-based check.
  - Redaction: chose salted field hashes over encryption with key deletion (key management too complex) and re-hashing (breaks tamper evidence). Chose a configured SENSITIVE_FIELDS list and a script trigger, keeping the public API append-only.
  - Export: kept resourceType required with resourceId, although the brief says "resourceId or actorId", for consistency with the query rule. Chose not to sign bundles; documented it as a limitation with the mitigation instead.
  - Redaction changes what Scenario A hashes, so updated scenario-a.md before building.
- **Commit:** fd9be51f
