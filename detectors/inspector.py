"""Main entry point: inspect(text, direction, ctx) runs every detector once."""
from contracts.schemas import Finding

from .confidential import detect_confidential
from .credentials import detect_credentials
from .scan import detect_all

DIRECTIONS = ("prompt", "response")

# Lower number wins when two token-level findings overlap.
_CATEGORY_PRIORITY = {"CREDENTIAL": 0, "FINANCIAL": 1, "PII": 2}
# Whole-document findings are kept even when they contain other findings.
_DOCUMENT_LEVEL = {"CONFIDENTIAL"}


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.start < b.end and b.start < a.end


def inspect(text: str, direction: str = "prompt", ctx=None) -> list[Finding]:
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of {DIRECTIONS}, got {direction!r}")
    if not text:
        return []

    token_level = [f for f in detect_all(text) + detect_credentials(text)]
    token_level.sort(key=lambda f: (_CATEGORY_PRIORITY.get(f.category, 9), -f.confidence, f.start))
    kept: list[Finding] = []
    for f in token_level:
        if not any(_overlaps(f, k) for k in kept):
            kept.append(f)

    document_level = [f for f in detect_confidential(text) if f.category in _DOCUMENT_LEVEL]
    return sorted(kept + document_level, key=lambda f: (f.start, f.end))


def summarize_findings(findings: list[Finding]) -> list[dict]:
    """One row per type: {type, count, confidence} with the highest confidence seen."""
    rows: dict[str, dict] = {}
    for f in findings:
        row = rows.setdefault(f.type, {"type": f.type, "count": 0, "confidence": 0.0})
        row["count"] += 1
        row["confidence"] = max(row["confidence"], f.confidence)
    return sorted(rows.values(), key=lambda r: r["type"])
