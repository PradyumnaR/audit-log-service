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

## #4 — Updated with scenario-c and add architecture for scenario-b & scenario-c (2026-09-27)

- **Category:** Analysis/Design
- **Prompt:** Update docs/architecture.md with scenario-b and scenario-c using the questions and decisions from the scenario docs, extending Summary and adding one Architecture table row per scenario in the same structure as scenario-a, without deleting or changing existing content.
- **Decision:** Accepted
- **Rationale:** Reviewd scenario-c.md file decisions updated in architecture.md file
- **Commit:** 6a25cb7

## #5 — feat: scenario-a Tasks: A1 & A2 (2026-09-27)

- **Category:** Implementation, Test generation
- **Prompt:** Implement A1 and A2 from docs/scenario-a.md: the audit_events table (snake_case columns including archived, field_hashes, field_salts) and a single reusable hashing module using SHA-256 over canonical JSON, with salted field hashes for SENSITIVE_FIELDS used in place of raw values in the content hash, and no endpoints. Acceptance: unit tests show key-order independence, that changing any hashed field changes the hash, and that sensitive fields hash via their field hash; make check passes.
- **Decision:** Accepted
- **Rationale:** Verified table schema changes, hash logic, Ran test cases.
- **Commit:** a9ca00b

## #6 — scenario-a Tasks: A3 (2026-09-27)

- **Category:** Implementation, Test generation
- **Prompt:** Implement A3 from docs/scenario-a.md (save with chain link) following the decisions in docs/scenario-a.md and docs/scenario-b.md, reusing the A2 hashing module. Include a test that runs 5 simultaneous writes and checks the chain is still unbroken; make check passes.
- **Decision:** Accepted
- **Rationale:** Checked code changes, ran make test to inspect hashing link changes
- **Commit:** 705c336

## #7 — Scenario-a Task: A4 (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement A4 from docs/scenario-a.md (POST /audit/events) following the decisions in docs/scenario-a.md and docs/scenario-b.md, reusing the append logic from A3; make check passes.
- **Decision:** Accepted
- **Rationale:** Checked code changes, tested POST /audit/events using swagger fastapi.
- **Commit:** 309f81b

## #8 — docs: restructuring (scenario-a & architecture) (2026-09-27)

- **Category:** Documentation
- **Prompt:** Move the Implementation section (Hashing, Appending to the chain, API: POST, Configuration) from docs/architecture.md into section 6. Execution notes of docs/scenario-a.md as a table of at most 10 rows.
- **Decision:** Accepted
- **Rationale:** Checked scenario-a.md file and make sure relavent information is added in execution notes
- **Commit:** 17862b2

## #9 — scenario-a Task: A5 (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement A5 from docs/scenario-a.md (GET /audit/events) following the decisions in docs/scenario-a.md and docs/scenario-b.md, reusing existing modules, with unit and integration tests; make check passes. Add A5 execution notes to docs/scenario-a.md without modifying existing notes, following the existing table format.
- **Decision:** Accepted
- **Rationale:** Checked code changes, tested GET /audit/events using swagger fastapi
- **Commit:** 2d7a969

## #10 — scenario-a Tasks: A6 & A7 (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement A6 (verify logic) and A7 (GET /audit/verify) from docs/scenario-a.md following the decisions in docs/scenario-a.md and docs/scenario-b.md, reusing the A2 hashing module, with verify logic in the domain layer and a thin endpoint; unit tests for the logic, integration tests for the endpoint, make check passes. Add execution notes for each task to docs/scenario-a.md without modifying existing notes, following the existing table format.
- **Decision:** Accepted
- **Rationale:** Checked code changes, tested GET /audit/verify using swagger fastapi. Deleted records in the DB and checked response.
- **Commit:** 0f4e5b7

## #11 — scenario-b Tasks: B1 & B2 (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement B1 (archive columns + retention script) and B2 (verify handles archived records) from docs/scenario-b.md following its decisions, adding a make retention target that runs scripts/run_retention.py and reusing the existing verify logic extended for archived records and INVALID_ARCHIVE; make check passes.
- **Decision:** Modified
- **Rationale:** Remove retention days value form .env config value. Instead Use timestamp passed by the operator while running script
- **Commit:** c31eac6

## #12 — scenario-b Task: B1 & B2 modified (2026-09-27)

- **Category:** Implementation
- **Prompt:** Change retention per docs/scenario-b.md: remove RETENTION_DAYS entirely (config, .env.example, validation); scripts/run_retention.py takes a required --before argument (ISO 8601 UTC with Z) and archives records with timestamp strictly earlier than it, rejecting missing, invalid, or future values. Update the Makefile so make retention BEFORE=... passes it through, update tests; make check passes.
- **Decision:** Accepted
- **Rationale:** Modified logic to pass retention time as a parameter to script. Look at Makefile how th param is passed
- **Commit:** 96fb68e

## #13 — scenario-b redaction logic (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement B3 and B4 from docs/scenario-b.md, adding scripts/redact.py and a make redact target (make redact ID=… FIELD=…), reusing the existing hashing and verify logic; make check passes.
- **Decision:** Accepted
- **Rationale:** Run redact script; verified GET, /aduit/verify api's
- **Commit:** 353febb

## #14 — scenario-b export & verify bundle (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement B5, B6 and B7 from docs/scenario-b.md: the GET /audit/export endpoint returning a verifiable bundle for an actorId or resourceType + resourceId, a stdlib-only scripts/verify_bundle.py offline verifier, and retention/redaction tests; make check passes.
- **Decision:** Accepted
- **Rationale:** Verified code changes; exported bundle; verified bundle againt verify script
- **Commit:** 42e744e

## #15 — scenario-c (2026-09-27)

- **Category:** Implementation
- **Prompt:** Implement C1, C2 and C3 from docs/scenario-c.md: document the account access event convention with a sample ACCOUNT_VIEWED event in scenario-c.md and the README, add GET /audit/reports/account-access (required from/to, optional resourceId or actorId, reusing GET /audit/events query logic, pagination and archived/redacted handling) with tests, and update execution notes without editing docs/architecture.md; make check passes.
- **Decision:** TODO (engineer)
- **Rationale:** TODO (engineer)
- **Commit:** ce184c5
