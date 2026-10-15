"""Runs every PII detector together and provides masking helpers."""
from contracts.schemas import Finding

from .generic_pii import detect_card, detect_email
from .india_pii import detect_india_pii


def detect_all(text: str) -> list[Finding]:
    emails = detect_email(text)
    others = [
        f
        for f in detect_india_pii(text) + detect_card(text)
        # Anything found inside an email address (9876543210@x.com) belongs to the email.
        if not any(e.start <= f.start and f.end <= e.end for e in emails)
    ]
    return sorted(emails + others, key=lambda f: (f.start, f.end))


def mask_preview(value: str, keep: int = 4) -> str:
    """Hide all but the last `keep` letters or digits, keeping separators."""
    alnum_total = sum(ch.isalnum() for ch in value)
    seen = 0
    out = []
    for ch in value:
        if not ch.isalnum():
            out.append(ch)
            continue
        seen += 1
        out.append(ch if seen > alnum_total - keep else "X")
    return "".join(out)


def mask_text(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with [TYPE]. Overlapping spans are merged."""
    spans = sorted((f.start, f.end, f.type) for f in findings if f.start is not None)
    result = []
    pos = 0
    for start, end, type_ in spans:
        if start < pos:
            continue
        result.append(text[pos:start])
        result.append(f"[{type_}]")
        pos = end
    result.append(text[pos:])
    return "".join(result)
