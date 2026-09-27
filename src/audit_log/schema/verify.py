"""Pydantic response model for ``GET /audit/verify``."""

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from audit_log.domain.verification import VerificationResult, ViolationType


class VerifyResponse(BaseModel):
    """Chain status. The violation fields are omitted when the chain is intact."""

    model_config = ConfigDict(alias_generator=to_camel, validate_by_name=True)

    intact: bool
    records_checked: int
    first_broken_record_id: int | None = None
    violation_type: ViolationType | None = None
    detail: str | None = None

    @classmethod
    def from_result(cls, result: VerificationResult) -> "VerifyResponse":
        violation = result.violation
        if violation is None:
            return cls(intact=True, records_checked=result.records_checked)
        return cls(
            intact=False,
            records_checked=result.records_checked,
            first_broken_record_id=violation.record_id,
            violation_type=violation.violation_type,
            detail=violation.detail,
        )
