.PHONY: install run test lint typecheck security check

install:
	uv sync

run:
	uv run uvicorn audit_log.api.app:app --reload

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
