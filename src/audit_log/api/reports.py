"""``/audit/reports`` routes: read-only compliance reports (scenario C)."""

from typing import Annotated

from fastapi import APIRouter, Query

from audit_log.api.dependencies import SessionDep
from audit_log.schema.events import EventList
from audit_log.schema.reports import AccountAccessQuery
from audit_log.storage.repository import query_events

router = APIRouter(prefix="/audit/reports", tags=["reports"])


@router.get("/account-access")
def account_access(query: Annotated[AccountAccessQuery, Query()], session: SessionDep) -> EventList:
    """Who viewed, updated, or exported ACCOUNT data in ``[from, to)``, in id order.

    Same pagination, archived exclusion and ``[REDACTED]`` masking as ``GET /audit/events``.
    """
    page = query_events(session, query.to_filter(), limit=query.limit, after_id=query.after_id)
    return EventList.from_page(page)
