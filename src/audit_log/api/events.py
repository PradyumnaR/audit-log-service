"""``/audit/events`` routes.

Append-only: records can be created (and, from A5, queried) but there is deliberately no
update or delete route, so PUT/PATCH/DELETE answer 405 Method Not Allowed.
"""

from fastapi import APIRouter, status

from audit_log.api.dependencies import SessionDep
from audit_log.schema.events import EventCreate, EventCreated
from audit_log.storage.repository import append_event

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
