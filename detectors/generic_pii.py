"""Generic PII detectors that are not India-specific: email addresses and payment cards (Luhn)."""
import re

from contracts.schemas import Finding

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9-])"
)

# 13 to 19 digits, optionally grouped by single spaces or hyphens, and not
# part of a longer digit run.
_CARD_RE = re.compile(r"(?<!\d)(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)")
_CARD_CONTEXT = re.compile(
    r"\b(?:card|credit|debit|visa|mastercard|rupay|amex|cvv|expiry)\b", re.I
)
_CONTEXT_WINDOW = 40


def luhn_valid(number: str) -> bool:
    if not number or not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_email(text: str) -> list[Finding]:
    return [
        Finding(
            category="PII",
            type="EMAIL",
            start=m.start(),
            end=m.end(),
            confidence=0.9,
            detector="regex",
        )
        for m in _EMAIL_RE.finditer(text)
    ]


def detect_card(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if not 13 <= len(digits) <= 19 or not luhn_valid(digits):
            continue
        lo = max(0, m.start() - _CONTEXT_WINDOW)
        near = _CARD_CONTEXT.search(text, lo, min(len(text), m.end() + _CONTEXT_WINDOW))
        findings.append(
            Finding(
                category="FINANCIAL",
                type="CARD",
                start=m.start(),
                end=m.end(),
                confidence=0.95 if near else 0.8,
                detector="regex+luhn",
            )
        )
    return findings
