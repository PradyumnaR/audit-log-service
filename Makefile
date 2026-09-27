.PHONY: install run test lint typecheck security check retention

install:
	uv sync

run:
	uv run uvicorn audit_log.api.app:app --reload

# Operator task: archive records older than RETENTION_DAYS (read from .env when present).
retention:
	uv run $(if $(wildcard .env),--env-file .env) python scripts/run_retention.py

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
