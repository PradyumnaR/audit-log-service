"""Unit tests for the GET /audit/verify response model."""

from audit_log.domain.verification import VerificationResult, Violation, ViolationType
from audit_log.schema.verify import VerifyResponse


def test_intact_response_has_no_violation_fields() -> None:
    response = VerifyResponse.from_result(VerificationResult(records_checked=120))
    assert response.model_dump(by_alias=True, exclude_none=True) == {
        "intact": True,
        "recordsChecked": 120,
    }


def test_broken_response_reports_first_violation() -> None:
    result = VerificationResult(
        records_checked=42,
        violation=Violation(42, ViolationType.CONTENT_HASH_MISMATCH, "Stored contentHash differs"),
    )
    assert VerifyResponse.from_result(result).model_dump(mode="json", by_alias=True) == {
        "intact": False,
        "recordsChecked": 42,
        "firstBrokenRecordId": 42,
        "violationType": "CONTENT_HASH_MISMATCH",
        "detail": "Stored contentHash differs",
    }
