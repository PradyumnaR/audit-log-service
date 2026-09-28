"""Unit tests for scripts/verify_bundle.py: parity with the service's hashing and tampering."""

import ast
import copy
import json
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

import verify_bundle
from audit_log.domain import hashing
from audit_log.schema.export import ExportBundle, ExportQuery
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import (
    EventFilter,
    NewEvent,
    append_event,
    export_events,
    redact_field,
)

SCRIPT = Path(verify_bundle.__file__)
NOW = datetime(2026, 9, 27, 10, 0, 0, tzinfo=UTC)
SENSITIVE = ("accountNumber", "taxId")

# Values whose serialization is easy to get subtly wrong.
TRICKY_VALUES: list[Any] = [
    "plain",
    "naïve \u2013 ünïcödé ✓ 日本",
    'quote " backslash \\ newline \n tab \t',
    0,
    -17,
    2**63,
    1.5,
    1e-7,
    0.1 + 0.2,
    True,
    None,
    [],
    {},
    {"b": [1, {"d": 2, "c": 1}], "a": None},
]


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _export(session: Session) -> dict[str, Any]:
    """Export like the endpoint does, as the JSON a recipient would load."""
    query = ExportQuery.model_validate({"actorId": "user-1042"})
    records = export_events(session, EventFilter(actor_id="user-1042"))
    bundle = ExportBundle.build(query, records, sensitive_fields=SENSITIVE, exported_at=NOW)
    data: dict[str, Any] = json.loads(bundle.model_dump_json(by_alias=True))
    return data


@pytest.fixture
def bundle(engine: Engine) -> dict[str, Any]:
    """Four consecutive records for user-1042; record 3 has accountNumber redacted."""
    with Session(engine) as session:
        for value in ("0000-TEST", "1111-TEST", "2222-TEST", "3333-TEST"):
            payload = {"accountNumber": value, "taxId": "000-00-0000", "field": "x", "n": 1.5}
            new_event = NewEvent("RECORD_UPDATED", "user-1042", "ACCOUNT", "acct-88731", payload)
            append_event(session, new_event, sensitive_fields=SENSITIVE, now=lambda: NOW)
        redact_field(session, 3, "accountNumber", sensitive_fields=SENSITIVE)
        return _export(session)


def _error(data: Any) -> str:
    result = verify_bundle.verify_bundle(data)
    assert result.error is not None, "expected verification to fail"
    return str(result.error)


# --- Parity with audit_log.domain.hashing ----------------------------------------------


def test_script_uses_only_the_standard_library() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported
    assert imported <= sys.stdlib_module_names


def test_constants_match_service() -> None:
    assert verify_bundle.HASH_ALGORITHM == hashing.HASH_ALGORITHM
    assert verify_bundle.SALT_BYTES == hashing.SALT_BYTES
    from audit_log.schema.events import REDACTED

    assert verify_bundle.REDACTED == REDACTED


@pytest.mark.parametrize("value", TRICKY_VALUES)
def test_canonical_json_and_field_hash_match_service(value: Any) -> None:
    salt = hashing.generate_salt()
    assert verify_bundle.canonical_json(value) == hashing.canonical_json(value)
    assert verify_bundle.compute_field_hash(salt, value) == hashing.compute_field_hash(salt, value)


@pytest.mark.parametrize("value", TRICKY_VALUES)
def test_content_hash_matches_service(value: Any) -> None:
    field_hashes = {"accountNumber": "c" * 64}
    fields: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-ü",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "timestamp": "2026-09-27T10:00:00Z",
        "payload": {"value": value, "accountNumber": "0000-TEST"},
        "field_hashes": field_hashes,
        "previous_hash": hashing.GENESIS_HASH,
    }
    record = {
        "eventType": fields["event_type"],
        "actorId": fields["actor_id"],
        "resourceType": fields["resource_type"],
        "resourceId": fields["resource_id"],
        "timestamp": fields["timestamp"],
        "payload": fields["payload"],
        "fieldHashes": field_hashes,
        "previousHash": fields["previous_hash"],
    }
    assert verify_bundle.compute_content_hash(record) == hashing.compute_content_hash(**fields)


def test_bundle_hash_matches_service() -> None:
    hashes = [hashing.sha256_hex(str(i).encode()) for i in range(5)]
    assert verify_bundle.compute_bundle_hash(hashes) == hashing.compute_bundle_hash(hashes)
    assert verify_bundle.compute_bundle_hash([]) == hashing.compute_bundle_hash([])


# --- Verification ------------------------------------------------------------------------


def test_untouched_bundle_is_intact(bundle: dict[str, Any]) -> None:
    result = verify_bundle.verify_bundle(bundle)
    assert result.intact
    assert result.record_count == 4


def test_empty_bundle_is_intact(engine: Engine) -> None:
    with Session(engine) as session:
        assert verify_bundle.verify_bundle(_export(session)).intact


def test_non_consecutive_ids_skip_link_check(engine: Engine) -> None:
    with Session(engine) as session:
        for actor in ("user-1042", "user-2001", "user-1042"):
            new_event = NewEvent("RECORD_UPDATED", actor, "ACCOUNT", "acct-88731", {"f": 1})
            append_event(session, new_event, sensitive_fields=(), now=lambda: NOW)
        data = _export(session)
    assert [record["id"] for record in data["records"]] == [1, 3]
    assert verify_bundle.verify_bundle(data).intact


Tamper = Callable[[dict[str, Any]], None]


def _set(path: str, value: Any) -> Tamper:
    """Set ``records[i].key[.subkey]`` (e.g. ``"1.payload.field"``) to ``value``."""

    def tamper(data: dict[str, Any]) -> None:
        index, *keys = path.split(".")
        target = data["records"][int(index)]
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value

    return tamper


def _remove(index: int, *, fix_count: bool = False) -> Tamper:
    def tamper(data: dict[str, Any]) -> None:
        del data["records"][index]
        if fix_count:
            data["metadata"]["recordCount"] -= 1

    return tamper


def _swap(data: dict[str, Any]) -> None:
    records = data["records"]
    records[0], records[1] = records[1], records[0]


def _duplicate_last(data: dict[str, Any]) -> None:
    data["records"].append(copy.deepcopy(data["records"][-1]))
    data["metadata"]["recordCount"] += 1


def _unredact_without_salt(data: dict[str, Any]) -> None:
    data["records"][2]["payload"]["accountNumber"] = "9999-TEST"


def _rehash_after_edit(data: dict[str, Any]) -> None:
    # Edit record 1 and recompute its content hash: the next record no longer links to it.
    record = data["records"][0]
    record["payload"]["field"] = "edited"
    record["contentHash"] = verify_bundle.compute_content_hash(record)


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        pytest.param(_set("1.payload.field", "edited"), "contentHash does not match", id="payload"),
        pytest.param(_set("1.actorId", "user-2001"), "export filter", id="actor-off-filter"),
        pytest.param(_set("1.resourceId", "acct-00001"), "contentHash", id="resource"),
        pytest.param(_set("1.timestamp", "2026-01-01T00:00:00Z"), "contentHash", id="time"),
        pytest.param(_set("1.eventType", "RECORD_DELETED"), "contentHash", id="event-type"),
        pytest.param(_set("1.payload.n", 1.50001), "contentHash", id="number"),
        pytest.param(_set("1.payload.accountNumber", "9999-TEST"), "field hash", id="sensitive"),
        pytest.param(_set("1.fieldSalts.accountNumber", "00" * 32), "field hash", id="salt"),
        pytest.param(_set("1.fieldSalts.accountNumber", 5), "field hash", id="salt-type"),
        pytest.param(_set("1.fieldSalts.extra", "00" * 32), "no field hash", id="extra-salt"),
        pytest.param(_set("1.fieldHashes.accountNumber", "0" * 64), "contentHash", id="fh"),
        pytest.param(_set("1.contentHash", "0" * 64), "contentHash", id="content-hash"),
        pytest.param(_set("1.previousHash", "0" * 64), "contentHash", id="previous-hash"),
        pytest.param(_unredact_without_salt, "not [REDACTED]", id="unredact"),
        pytest.param(_set("2.fieldSalts.accountNumber", "00" * 32), "field hash", id="salt-back"),
        pytest.param(_rehash_after_edit, "previousHash does not match", id="rehashed-edit"),
        pytest.param(_remove(1), "recordCount", id="removed"),
        pytest.param(_remove(3, fix_count=True), "bundleHash", id="removed-count-fixed"),
        pytest.param(_duplicate_last, "not strictly increasing", id="added-duplicate"),
        pytest.param(_swap, "not strictly increasing", id="reordered"),
    ],
)
def test_tampering_is_detected(bundle: dict[str, Any], tamper: Tamper, message: str) -> None:
    tamper(bundle)
    assert message in _error(bundle)


def test_changed_bundle_hash_is_detected(bundle: dict[str, Any]) -> None:
    bundle["bundleHash"] = "0" * 64
    assert "bundleHash" in _error(bundle)


def test_error_names_the_record(bundle: dict[str, Any]) -> None:
    bundle["records"][1]["payload"]["field"] = "edited"
    result = verify_bundle.verify_bundle(bundle)
    assert result.error is not None
    assert result.error.record_id == 2


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        pytest.param(lambda d: d.clear(), "metadata is missing", id="empty"),
        pytest.param(lambda d: d.update(records={}), "records is missing", id="records"),
        pytest.param(lambda d: d.pop("bundleHash"), "bundleHash is missing", id="bundle-hash"),
        pytest.param(
            lambda d: d["metadata"].update(hashAlgorithm="MD5"), "unsupported", id="algorithm"
        ),
        pytest.param(lambda d: d["metadata"].update(filter={}), "filter must use", id="no-filter"),
        pytest.param(
            lambda d: d["metadata"].update(filter={"eventType": "X"}), "filter", id="bad-filter"
        ),
        pytest.param(lambda d: d["records"].__setitem__(0, []), "not an object", id="record"),
        pytest.param(lambda d: d["records"][0].pop("id"), "integer id", id="no-id"),
        pytest.param(lambda d: d["records"][0].update(id=True), "integer id", id="bool-id"),
        pytest.param(lambda d: d["records"][0].pop("timestamp"), "timestamp", id="no-time"),
        pytest.param(lambda d: d["records"][0].update(payload=[]), "payload", id="payload"),
        pytest.param(lambda d: d["records"][0].pop("fieldSalts"), "fieldSalts", id="salts"),
        pytest.param(
            lambda d: d["records"][0]["payload"].update(x=float("nan")),
            "canonically serialized",
            id="nan",
        ),
    ],
)
def test_malformed_bundle_fails(
    bundle: dict[str, Any], mutate: Callable[[dict[str, Any]], Any], message: str
) -> None:
    mutate(bundle)
    assert message in _error(bundle)


def test_non_object_bundle_fails() -> None:
    assert "JSON object" in _error([])


# --- Command line ------------------------------------------------------------------------


def _write(tmp_path: Path, data: Any) -> str:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_main_intact(
    bundle: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert verify_bundle.main([_write(tmp_path, bundle)]) == 0
    assert "intact (4 record(s))" in capsys.readouterr().out


def test_main_failed(
    bundle: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["records"][1]["payload"]["field"] = "edited"
    assert verify_bundle.main([_write(tmp_path, bundle)]) == 1
    assert "FAILED: record 2: contentHash does not match" in capsys.readouterr().err


def test_main_failed_without_record(
    bundle: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["bundleHash"] = "0" * 64
    assert verify_bundle.main([_write(tmp_path, bundle)]) == 1
    assert "FAILED: bundleHash" in capsys.readouterr().err


@pytest.mark.parametrize("content", [None, "not json {"])
def test_main_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    path = tmp_path / "bundle.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert verify_bundle.main([str(path)]) == 2
    assert "cannot read" in capsys.readouterr().err
