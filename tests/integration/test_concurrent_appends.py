"""Parallel appends against a real SQLite file must still form one unbroken chain."""

import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from audit_log.domain.hashing import GENESIS_HASH, compute_content_hash
from audit_log.storage.database import create_schema, make_engine
from audit_log.storage.models import AuditEvent
from audit_log.storage.repository import NewEvent, append_event

WRITERS = 5


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    # A file database: in-memory SQLite gives each thread its own separate database.
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    create_schema(engine)
    yield engine
    engine.dispose()


def _slow_clock() -> datetime:
    # Runs between reading the previous hash and inserting; widens the race window so an
    # unlocked implementation would have several writers link to the same previous hash.
    time.sleep(0.05)
    return datetime.now(UTC)


def test_five_simultaneous_writes_form_one_unbroken_chain(engine: Engine) -> None:
    start = threading.Barrier(WRITERS)

    def write(index: int) -> int:
        start.wait()
        with Session(engine) as session:
            record = append_event(
                session,
                NewEvent(
                    event_type="RECORD_UPDATED",
                    actor_id=f"user-{index}",
                    resource_type="ACCOUNT",
                    resource_id="acct-88731",
                    payload={"writer": index},
                ),
                sensitive_fields=(),
                now=_slow_clock,
            )
            return record.id

    with ThreadPoolExecutor(max_workers=WRITERS) as pool:
        ids = list(pool.map(write, range(WRITERS)))

    with Session(engine) as session:
        records = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()

    assert sorted(ids) == [record.id for record in records] == list(range(1, WRITERS + 1))
    assert {record.actor_id for record in records} == {f"user-{i}" for i in range(WRITERS)}
    assert records[0].previous_hash == GENESIS_HASH
    for previous, current in pairwise(records):
        assert current.previous_hash == previous.content_hash
        assert current.timestamp >= previous.timestamp
    assert len({record.previous_hash for record in records}) == WRITERS
    for record in records:
        assert record.event_type is not None
        assert record.actor_id is not None
        assert record.resource_type is not None
        assert record.resource_id is not None
        assert record.payload is not None
        assert record.content_hash == compute_content_hash(
            event_type=record.event_type,
            actor_id=record.actor_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            timestamp=record.timestamp,
            payload=record.payload,
            field_hashes=record.field_hashes,
            previous_hash=record.previous_hash,
        )
