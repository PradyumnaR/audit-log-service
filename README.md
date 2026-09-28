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
