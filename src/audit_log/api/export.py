"""``/audit/export`` route: read-only export of an offline-verifiable bundle."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from audit_log.api.dependencies import SessionDep
from audit_log.config import sensitive_fields
from audit_log.schema.export import ExportBundle, ExportQuery
from audit_log.storage.repository import export_events

router = APIRouter(prefix="/audit/export", tags=["export"])


@router.get("")
def export(query: Annotated[ExportQuery, Query()], session: SessionDep) -> ExportBundle:
    """Export every non-archived record for an actor or a resource, in id order.

    Redacted values appear as ``[REDACTED]``. Verify offline with ``scripts/verify_bundle.py``.
    """
    records = export_events(session, query.to_filter())
    return ExportBundle.build(
        query, records, sensitive_fields=sensitive_fields(), exported_at=datetime.now(UTC)
    )
