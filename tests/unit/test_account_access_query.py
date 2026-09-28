"""Unit tests for GET /audit/reports/account-access query validation and filter mapping."""

from typing import Any

import pytest
from pydantic import ValidationError

from audit_log.schema.events import DEFAULT_LIMIT, MAX_LIMIT
from audit_log.schema.reports import (
    ACCOUNT_ACCESS_EVENT_TYPES,
    ACCOUNT_RESOURCE_TYPE,
    AccountAccessQuery,
)
from audit_log.storage.repository import EventFilter

RANGE = {"from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z"}


def _query(**params: Any) -> AccountAccessQuery:
    # Query strings arrive as text, so validate string values as FastAPI does.
    return AccountAccessQuery.model_validate(params)


def test_access_event_convention() -> None:
    assert ACCOUNT_RESOURCE_TYPE == "ACCOUNT"
    assert frozenset({"ACCOUNT_VIEWED", "ACCOUNT_UPDATED", "ACCOUNT_EXPORTED"}) == (
        ACCOUNT_ACCESS_EVENT_TYPES
    )


def test_range_only_maps_to_account_access_filter() -> None:
    query = _query(**RANGE)
    assert query.limit == DEFAULT_LIMIT
    assert query.after_id is None
    assert query.to_filter() == EventFilter(
        event_types=ACCOUNT_ACCESS_EVENT_TYPES,
        resource_type="ACCOUNT",
        from_timestamp="2026-09-24T00:00:00Z",
        to_timestamp="2026-09-25T00:00:00Z",
    )


def test_optional_filters_map_to_event_filter() -> None:
    query = _query(**RANGE, resourceId="acct-88731", actorId="user-1042", limit="10", cursor="7")
    assert query.limit == 10
    assert query.after_id == 7
    assert query.to_filter() == EventFilter(
        event_types=ACCOUNT_ACCESS_EVENT_TYPES,
        actor_id="user-1042",
        resource_type="ACCOUNT",
        resource_id="acct-88731",
        from_timestamp="2026-09-24T00:00:00Z",
        to_timestamp="2026-09-25T00:00:00Z",
    )


def test_offsets_and_fractions_use_stored_bounds() -> None:
    query = _query(**{"from": "2026-09-24T02:00:00+02:00"}, to="2026-09-24T10:00:00.5Z")
    event_filter = query.to_filter()
    assert event_filter.from_timestamp == "2026-09-24T00:00:00Z"
    assert event_filter.to_timestamp == "2026-09-24T10:00:01Z"


@pytest.mark.parametrize(
    ("params", "message"),
    [
        pytest.param({"to": RANGE["to"]}, "from", id="missing-from"),
        pytest.param({"from": RANGE["from"]}, "to", id="missing-to"),
        pytest.param({}, "from", id="missing-both"),
        pytest.param({**RANGE, "from": RANGE["to"]}, "from must be earlier than to", id="empty"),
        pytest.param({**RANGE, "from": "2026-09-24T00:00:00"}, "ISO 8601", id="naive"),
        pytest.param({**RANGE, "resourceType": "ACCOUNT"}, "resourceType", id="resource-type"),
        pytest.param({**RANGE, "eventType": "ACCOUNT_VIEWED"}, "eventType", id="event-type"),
        pytest.param({**RANGE, "limit": str(MAX_LIMIT + 1)}, "limit", id="limit"),
        pytest.param({**RANGE, "actorId": ""}, "actorId", id="empty-actor"),
    ],
)
def test_invalid_queries_are_rejected(params: dict[str, str], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _query(**params)
