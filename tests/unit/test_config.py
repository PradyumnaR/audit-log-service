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


def test_retention_days_parses_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RETENTION_DAYS", " 30 ")
    assert config.retention_days() == 30


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        pytest.param(None, "not set", id="unset"),
        pytest.param("  ", "not set", id="blank"),
        pytest.param("thirty", "integer", id="not-integer"),
        pytest.param("1.5", "integer", id="fraction"),
        pytest.param("0", "at least 1", id="zero"),
        pytest.param("-7", "at least 1", id="negative"),
    ],
)
def test_retention_days_rejects_invalid(
    monkeypatch: pytest.MonkeyPatch, raw: str | None, message: str
) -> None:
    if raw is None:
        monkeypatch.delenv("RETENTION_DAYS", raising=False)
    else:
        monkeypatch.setenv("RETENTION_DAYS", raw)
    with pytest.raises(ValueError, match=message):
        config.retention_days()
