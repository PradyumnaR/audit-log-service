"""Unit tests for environment-driven configuration."""

import pytest

from audit_log import config


def test_sensitive_fields_default_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENSITIVE_FIELDS", raising=False)
    assert config.sensitive_fields() == frozenset()


def test_sensitive_fields_parses_comma_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSITIVE_FIELDS", " accountNumber, taxId,,")
    assert config.sensitive_fields() == frozenset({"accountNumber", "taxId"})


def test_database_url_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert config.database_url() == config.DEFAULT_DATABASE_URL


def test_database_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    assert config.database_url() == "sqlite://"
