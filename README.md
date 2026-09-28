## Tamper-evident, append-only audit log service.

## Account access events (compliance reporting)

Calling systems record access to client account data as normal events with
`resourceType` `ACCOUNT` and `eventType` `ACCOUNT_VIEWED`, `ACCOUNT_UPDATED`, or
`ACCOUNT_EXPORTED` (see docs/scenario-c.md). Sample `ACCOUNT_VIEWED` event for
`POST /audit/events`:

```json
{
  "eventType": "ACCOUNT_VIEWED",
  "actorId": "user-1042",
  "resourceType": "ACCOUNT",
  "resourceId": "acct-88731",
  "payload": { "channel": "web", "view": "account-summary" }
}
```

Regulators query them with
`GET /audit/reports/account-access?from=…&to=…[&resourceId=…][&actorId=…]`, which returns the
same paginated `{"items", "nextCursor"}` response as `GET /audit/events`.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.13.

```sh
make install    # uv sync (runtime + dev dependencies)
make run        # uvicorn dev server with reload
make test       # pytest with coverage (fails under 90%)
make lint       # ruff check + ruff format --check
make typecheck  # mypy --strict
make security   # bandit + pip-audit
make check      # all of the above gates
```

## Scripts

Operator scripts in `scripts/` use the same database as the service. Run them via `make`,
which loads `.env` if it exists, or directly with `uv run` (add `--env-file .env` to load it):

```sh
# Archive records older than a cutoff (ISO 8601 UTC with Z)
make retention BEFORE=2026-01-01T00:00:00Z
uv run python scripts/run_retention.py --before 2026-01-01T00:00:00Z

# Redact one sensitive payload field of one record
make redact ID=3 FIELD=accountNumber
uv run python scripts/redact.py --id 3 --field accountNumber

# Verify an exported bundle offline (standard library only, no service or database needed)
python scripts/verify_bundle.py bundle.json
```

Missing or invalid arguments exit with status 2. `redact.py` exits 1 if the redaction is
refused. `verify_bundle.py` exits 0 if the bundle is intact, 1 if verification fails, and 2
if the file can't be read or isn't JSON.

## Layout

```
src/audit_log/
  api/       FastAPI app and routers
  domain/    core audit/hash-chain logic
  schema/    Pydantic request/response models
  storage/   SQLAlchemy models and persistence
tests/
  unit/
  integration/
scripts/     developer/ops scripts
```
