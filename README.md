## Tamper-evident, append-only audit log service.

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
