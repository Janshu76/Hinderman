"""Maps Presidio entity names to the contract's types. Does not import Presidio itself."""
from contracts.schemas import Finding

PRESIDIO_TYPE_MAP: dict[str, tuple[str, str]] = {
    "PERSON": ("PERSON", "PII"),
    "EMAIL_ADDRESS": ("EMAIL", "PII"),
    "PHONE_NUMBER": ("PHONE", "PII"),
    "IN_PAN": ("PAN", "PII"),
    "IN_AADHAAR": ("AADHAAR", "PII"),
    "CREDIT_CARD": ("CARD", "FINANCIAL"),
}


def map_entity(entity_type: str) -> str | None:
    """Return the contract type for a Presidio entity name, or None if it has no home."""
    mapped = PRESIDIO_TYPE_MAP.get(entity_type)
    return mapped[0] if mapped else None


def to_finding(entity_type: str, start: int, end: int, score: float, min_score: float = 0.0) -> Finding | None:
    mapped = PRESIDIO_TYPE_MAP.get(entity_type)
    if mapped is None or score < min_score:
        return None
    type_, category = mapped
    return Finding(
        category=category,
        type=type_,
        start=start,
        end=end,
        confidence=max(0.0, min(1.0, float(score))),
        detector="presidio",
    )


def map_results(results, min_score: float = 0.0) -> list[Finding]:
    """Convert Presidio RecognizerResult objects (entity_type, start, end, score) to Findings."""
    findings = []
    for r in results:
        f = to_finding(r.entity_type, r.start, r.end, r.score, min_score)
        if f is not None:
            findings.append(f)
    return sorted(findings, key=lambda f: (f.start, f.end))
