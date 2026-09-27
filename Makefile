.PHONY: install run test lint typecheck security check retention

install:
	uv sync

run:
	uv run uvicorn audit_log.api.app:app --reload

# Operator task: archive records older than BEFORE (ISO 8601 UTC with Z), e.g.
#   make retention BEFORE=2026-01-01T00:00:00Z
retention:
	uv run $(if $(wildcard .env),--env-file .env) python scripts/run_retention.py $(if $(BEFORE),--before "$(BEFORE)")

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

security:
	uv run bandit -c pyproject.toml -r src
	uv run pip-audit --skip-editable

check: lint typecheck security test
