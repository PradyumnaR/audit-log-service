"""Smoke tests confirming the package layout is importable."""

import importlib

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "audit_log",
        "audit_log.api",
        "audit_log.domain",
        "audit_log.schema",
        "audit_log.storage",
    ],
)
def test_subpackage_importable(module: str) -> None:
    assert importlib.import_module(module) is not None
