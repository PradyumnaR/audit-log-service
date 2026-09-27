"""``/audit/events`` routes.

Append-only: records can be created and queried but there is deliberately no update or
delete route, so PUT/PATCH/DELETE answer 405 Method Not Allowed.
"""

from typing import Annotated

from fastapi import APIRouter, Query, status

from audit_log.api.dependencies import SessionDep
from audit_log.schema.events import EventCreate, EventCreated, EventList, EventQuery, EventRecord
from audit_log.storage.repository import append_event, query_events

router = APIRouter(prefix="/audit/events", tags=["events"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_event(body: EventCreate, session: SessionDep) -> EventCreated:
    """Append one event to the hash chain. The server assigns the timestamp."""
    record = append_event(session, body.to_new_event())
    return EventCreated(
        id=record.id,
        event_type=body.event_type,
        actor_id=body.actor_id,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        payload=body.payload,
        timestamp=record.timestamp,
    )


@router.get("")
def list_events(query: Annotated[EventQuery, Query()], session: SessionDep) -> EventList:
    """Query non-archived events in id order, with filters and cursor pagination."""
    page = query_events(session, query.to_filter(), limit=query.limit, after_id=query.after_id)
    return EventList(
        items=[EventRecord.from_record(record) for record in page.records],
        next_cursor=str(page.next_after_id) if page.next_after_id is not None else None,
    )
