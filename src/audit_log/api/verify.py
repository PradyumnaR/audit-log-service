"""``/audit/verify`` route: read-only hash chain verification."""

from fastapi import APIRouter

from audit_log.api.dependencies import SessionDep
from audit_log.domain.verification import verify_chain
from audit_log.schema.verify import VerifyResponse
from audit_log.storage.repository import iter_chain

router = APIRouter(prefix="/audit/verify", tags=["verify"])


@router.get("", response_model_exclude_none=True)
def verify(session: SessionDep) -> VerifyResponse:
    """Walk the whole chain; report intact, or the first broken record and why."""
    return VerifyResponse.from_result(verify_chain(iter_chain(session)))
