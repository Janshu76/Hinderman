from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError

from contracts.schemas import (
    Action, AuditEvent, AuditFinding, Category, Finding, GENESIS_HASH,
    KNOWN_TYPES, TYPE_CATEGORY, UserContext,
)


def finding(**overrides):
    data = dict(category="PII", type="PAN", start=2, end=12,
                confidence=0.85, detector="regex")
    data.update(overrides)
    return Finding(**data)


def audit_event(**overrides):
    data = dict(
        ts=datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        user_id="u1", direction="prompt", findings=[], action="allow",
        snippet_redacted="safe summary", content_sha256="a" * 64,
        prev_hash=GENESIS_HASH, latency_ms=10,
    )
    data.update(overrides)
    return AuditEvent(**data)


def test_known_types_are_derived_from_type_category():
    assert KNOWN_TYPES == frozenset(TYPE_CATEGORY)


@pytest.mark.parametrize("type_,category", TYPE_CATEGORY.items())
def test_every_known_type_accepts_its_canonical_category(type_, category):
    f = Finding(category=category, type=type_, confidence=0.5, detector="test")
    assert f.type == type_ and f.category == category


def test_unknown_type_is_rejected():
    with pytest.raises(ValidationError, match="Unknown finding type"):
        finding(type="NOT_A_REAL_TYPE")


def test_type_category_mismatch_is_rejected():
    with pytest.raises(ValidationError, match="requires category"):
        finding(category="FINANCIAL")


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_finding_confidence_out_of_range_is_rejected(confidence):
    with pytest.raises(ValidationError):
        finding(confidence=confidence)


def test_finding_offsets_are_inclusive_exclusive_valid_span():
    f = finding(start=0, end=1)
    assert f.start == 0 and f.end == 1


@pytest.mark.parametrize("start,end", [(-1, 2), (3, 3), (4, 3)])
def test_invalid_finding_offsets_are_rejected(start, end):
    with pytest.raises(ValidationError):
        finding(start=start, end=end)


def test_finding_offsets_must_both_be_set_or_both_none():
    with pytest.raises(ValidationError, match="both be set"):
        finding(start=1, end=None)
    assert finding(start=None, end=None).start is None


def test_user_context_accepts_contract_roles():
    user = UserContext(user_id="u4", role="admin", department="it", clearance=3)
    assert user.role == "admin" and user.clearance == 3


def test_user_context_rejects_invalid_role_and_clearance():
    with pytest.raises(ValidationError):
        UserContext(user_id="u1", role="owner", department="it", clearance=1)
    with pytest.raises(ValidationError):
        UserContext(user_id="u1", role="intern", department="it", clearance=4)


def test_audit_finding_contains_summary_not_raw_text():
    f = AuditFinding(type="PAN", count=2, confidence=0.9)
    assert f.model_dump() == {"type": "PAN", "count": 2, "confidence": 0.9}
    with pytest.raises(ValidationError):
        AuditFinding(type="PAN", count=0, confidence=0.9)


def test_audit_timestamp_is_normalized_to_utc():
    event = audit_event()
    assert event.ts.utcoffset() == timedelta(0)
    assert event.ts.hour == 18 and event.ts.minute == 30


def test_audit_timestamp_must_be_timezone_aware():
    with pytest.raises(ValidationError, match="timezone-aware"):
        audit_event(ts=datetime(2026, 1, 1))


@pytest.mark.parametrize("value", ["A" * 64, "g" * 64, "a" * 63, "A" * 64])
def test_audit_hashes_require_64_lowercase_hex(value):
    with pytest.raises(ValidationError):
        audit_event(content_sha256=value)


def test_audit_snippet_maximum_length_is_500():
    assert len(audit_event(snippet_redacted="x" * 500).snippet_redacted) == 500
    with pytest.raises(ValidationError):
        audit_event(snippet_redacted="x" * 501)


def test_audit_event_default_findings_is_independent():
    a = audit_event()
    b = audit_event()
    a.findings.append(AuditFinding(type="PAN", count=1, confidence=0.5))
    assert b.findings == []
