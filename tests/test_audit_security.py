import hashlib
import hmac

import pytest

from contracts.schemas import Finding
from gateway.audit import security

KEY = b"test-audit-hmac-key-that-is-long-enough-123"


def test_compute_content_hmac_matches_standard_hmac_sha256():
    expected = hmac.new(KEY, b"hello", hashlib.sha256).hexdigest()
    assert security.compute_content_hmac("hello", KEY) == expected


def test_content_hmac_changes_with_content_and_key():
    assert security.compute_content_hmac("hello", KEY) != security.compute_content_hmac("hello!", KEY)
    assert security.compute_content_hmac("hello", KEY) != security.compute_content_hmac("hello", b"another-long-key-for-testing-1234")


def test_load_hmac_key_requires_minimum_length(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "short")
    with pytest.raises(RuntimeError, match="at least 32"):
        security.load_hmac_key()


def test_load_hmac_key_returns_key_and_id(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "x" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY_ID", "rotation-2")
    assert security.load_hmac_key() == (b"x" * 40, "rotation-2")


def test_scrub_snippet_redacts_common_sensitive_patterns():
    raw = "PAN ABCPE1234F email rahul@gmail.com phone 9876543210 key AKIAIOSFODNN7EXAMPLE"
    cleaned = security.scrub_snippet(raw)
    for secret in ("ABCPE1234F", "rahul@gmail.com", "9876543210", "AKIAIOSFODNN7EXAMPLE"):
        assert secret not in cleaned
    assert "[PAN_REDACTED]" in cleaned
    assert "[EMAIL_REDACTED]" in cleaned
    assert "[PHONE_REDACTED]" in cleaned
    assert "[SECRET_REDACTED]" in cleaned


def test_truncate_snippet_respects_limit_and_ellipsis():
    result = security.truncate_snippet("x" * 700, 100)
    assert len(result) == 100 and result.endswith("…")


def test_truncate_snippet_does_not_cut_inside_redaction_token():
    result = security.truncate_snippet("safe text [SENSITIVE_TOKEN] more text", 20)
    assert result.endswith("…")
    assert "[SENS" not in result


def test_make_snippet_scrubs_then_truncates():
    result = security.make_snippet("contact 9876543210 " + "x" * 600, limit=80)
    assert len(result) <= 80
    assert "9876543210" not in result


def test_summarize_findings_groups_by_type_and_keeps_highest_confidence():
    findings = [
        Finding(category="PII", type="PAN", start=0, end=10, confidence=0.6, detector="a"),
        Finding(category="PII", type="PAN", start=11, end=21, confidence=0.9, detector="a"),
        Finding(category="PII", type="EMAIL", start=22, end=35, confidence=0.8, detector="b"),
    ]
    summaries = security.summarize_findings(findings)
    assert [(x.type, x.count, x.confidence) for x in summaries] == [
        ("EMAIL", 1, 0.8), ("PAN", 2, 0.9)
    ]
    assert all(not hasattr(x, "text") for x in summaries)
