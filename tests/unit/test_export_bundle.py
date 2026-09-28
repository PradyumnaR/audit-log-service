"""Unit tests for the export bundle: query validation, record mapping, bundle hash."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from audit_log.domain.hashing import (
    HASH_ALGORITHM,
    SERIALIZATION,
    canonical_json,
    compute_bundle_hash,
    sha256_hex,
)
from audit_log.schema.events import REDACTED
from audit_log.schema.export import ExportBundle, ExportQuery
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.repository import (
    EventFilter,
    NewEvent,
    append_event,
    archive_before,
    export_events,
    redact_field,
)

NOW = datetime(2026, 9, 27, 10, 0, 0, tzinfo=UTC)
SENSITIVE = ("accountNumber",)


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_engine("sqlite://")
    create_schema(engine)
    yield engine
    engine.dispose()


def _query(**params: Any) -> ExportQuery:
    return ExportQuery.model_validate(params)


def _append(session: Session, moment: datetime = NOW, **overrides: Any) -> None:
    values: dict[str, Any] = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1042",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-88731",
        "payload": {"accountNumber": "0000-TEST", "field": "mailingAddress"},
    }
    values.update(overrides)
    append_event(session, NewEvent(**values), sensitive_fields=SENSITIVE, now=lambda: moment)


def test_bundle_hash_is_sha256_of_canonical_content_hash_array() -> None:
    hashes = ["a" * 64, "b" * 64]
    assert compute_bundle_hash(hashes) == sha256_hex(canonical_json(hashes).encode("utf-8"))
    assert compute_bundle_hash(reversed(hashes)) != compute_bundle_hash(hashes)
    assert compute_bundle_hash(hashes[:1]) != compute_bundle_hash(hashes)


def test_query_by_actor_and_by_resource() -> None:
    assert _query(actorId="user-1042").to_filter() == EventFilter(actor_id="user-1042")
    by_resource = _query(resourceType="ACCOUNT", resourceId="acct-88731")
    assert by_resource.to_filter() == EventFilter(resource_type="ACCOUNT", resource_id="acct-88731")
    assert by_resource.described() == {"resourceType": "ACCOUNT", "resourceId": "acct-88731"}


@pytest.mark.parametrize(
    ("params", "message"),
    [
        pytest.param({}, "requires actorId", id="none"),
        pytest.param({"resourceId": "acct-88731"}, "resourceId requires resourceType", id="id"),
        pytest.param({"resourceType": "ACCOUNT"}, "requires resourceId", id="type-only"),
        pytest.param(
            {"actorId": "user-1042", "resourceType": "ACCOUNT", "resourceId": "acct-88731"},
            "not both",
            id="both",
        ),
        pytest.param({"eventType": "RECORD_UPDATED", "actorId": "u"}, "Extra", id="unknown"),
        pytest.param({"actorId": " user"}, "pattern", id="bad-actor"),
        pytest.param({"resourceType": "account", "resourceId": "a"}, "pattern", id="bad-type"),
    ],
)
def test_query_rejects(params: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _query(**params)


def test_export_events_returns_live_matching_records_in_id_order(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session, datetime(2026, 1, 1, tzinfo=UTC))
        _append(session, actor_id="user-2001")
        _append(session, resource_id="acct-00001")
        _append(session)
        archive_before(session, datetime(2026, 6, 1, tzinfo=UTC))
        by_actor = export_events(session, EventFilter(actor_id="user-1042"))
        by_resource = export_events(
            session, EventFilter(resource_type="ACCOUNT", resource_id="acct-88731")
        )
        assert [record.id for record in by_actor] == [3, 4]
        assert [record.id for record in by_resource] == [2, 4]


def test_bundle_contents(engine: Engine) -> None:
    with Session(engine) as session:
        _append(session)
        _append(session)
        redact_field(session, 2, "accountNumber", sensitive_fields=SENSITIVE)
        records = export_events(session, EventFilter(actor_id="user-1042"))
        bundle = ExportBundle.build(
            _query(actorId="user-1042"), records, sensitive_fields=SENSITIVE, exported_at=NOW
        )
        data = bundle.model_dump(by_alias=True)
        first, second = records

    assert data["metadata"] == {
        "exportedAt": "2026-09-27T10:00:00Z",
        "filter": {"actorId": "user-1042"},
        "hashAlgorithm": HASH_ALGORITHM,
        "serialization": SERIALIZATION,
        "sensitiveFields": ["accountNumber"],
        "recordCount": 2,
    }
    assert data["bundleHash"] == compute_bundle_hash([first.content_hash, second.content_hash])
    unredacted, redacted = data["records"]
    assert unredacted["payload"] == {"accountNumber": "0000-TEST", "field": "mailingAddress"}
    assert unredacted["fieldHashes"] == first.field_hashes
    assert unredacted["fieldSalts"] == first.field_salts
    assert unredacted["contentHash"] == first.content_hash
    assert unredacted["previousHash"] == first.previous_hash
    assert redacted["payload"] == {"accountNumber": REDACTED, "field": "mailingAddress"}
    assert redacted["fieldHashes"] == second.field_hashes
    assert redacted["fieldSalts"] == {}
    assert "archived" not in redacted


def test_empty_bundle() -> None:
    bundle = ExportBundle.build(_query(actorId="nobody"), [], sensitive_fields=(), exported_at=NOW)
    assert bundle.records == []
    assert bundle.metadata.record_count == 0
    assert bundle.bundle_hash == compute_bundle_hash([])
