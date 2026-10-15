"""Audit-service helpers: keyed hashing, snippet scrubbing, safe truncation."""
import hashlib
import hmac
import os
import re
from collections.abc import Sequence

from contracts.schemas import AuditFinding, Finding
from detectors.confidential import detect_confidential
from detectors.credentials import detect_credentials
from detectors.scan import detect_all, mask_text

MIN_KEY_CHARS = 32
SNIPPET_LIMIT = 500

_SCRUB_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"), "[NUMBER_REDACTED]"),
    (re.compile(r"(?<!\w)[A-Z]{5}[0-9]{4}[A-Z](?!\w)"), "[PAN_REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL_REDACTED]"),
    (re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"), "[PHONE_REDACTED]"),
    (re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,})\b"),
     "[SECRET_REDACTED]"),
]


def load_hmac_key() -> tuple[bytes, str]:
    """Return (key, key_id) from AUDIT_HMAC_KEY and AUDIT_HMAC_KEY_ID."""
    key = os.environ.get("AUDIT_HMAC_KEY", "")
    if len(key) < MIN_KEY_CHARS:
        raise RuntimeError(
            f"AUDIT_HMAC_KEY must be set and at least {MIN_KEY_CHARS} characters"
        )
    return key.encode("utf-8"), os.environ.get("AUDIT_HMAC_KEY_ID", "k1")


def compute_content_hmac(content: str, key: bytes) -> str:
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()


def scrub_snippet(text: str) -> str:
    for pattern, replacement in _SCRUB_RULES:
        text = pattern.sub(replacement, text)
    findings = detect_all(text) + detect_credentials(text) + detect_confidential(text)
    return mask_text(text, findings)


def truncate_snippet(text: str, limit: int = SNIPPET_LIMIT) -> str:
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    open_idx = cut.rfind("[")
    if open_idx != -1 and "]" not in cut[open_idx:]:
        cut = cut[:open_idx]
    return cut + "\u2026"


def make_snippet(masked_text: str, limit: int = SNIPPET_LIMIT) -> str:
    return truncate_snippet(scrub_snippet(masked_text), limit)


def summarize_findings(findings: Sequence[Finding]) -> list[AuditFinding]:
    """One AuditFinding per type: count and highest confidence. No offsets, no text."""
    grouped: dict[str, list[float]] = {}
    for f in findings:
        grouped.setdefault(f.type, []).append(f.confidence)
    return [
        AuditFinding(type=t, count=len(c), confidence=max(c))
        for t, c in sorted(grouped.items())
    ]
