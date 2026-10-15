"""India-specific PII detectors: Aadhaar (Verhoeff), PAN, phone, GSTIN, IFSC and UPI."""
import re

from contracts.schemas import Finding

from .verhoeff import is_valid as verhoeff_valid

# Lookarounds stop a match inside a longer digit run, even one split by
# spaces or hyphens (e.g. a 16-digit card number).
_AADHAAR_RE = re.compile(
    r"(?<!\d)(?<!\d[ -])"
    r"[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}"
    r"(?![ -]?\d)"
)
_AADHAAR_CONTEXT = re.compile(r"\b(?:aadhaar|aadhar|uidai)\b|आधार", re.I)

_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.I)
_PAN_HOLDER_TYPES = frozenset("PCHFATBLJG")
_PAN_CONTEXT = re.compile(r"\bpan\b|permanent account number", re.I)

_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:(?:\+91|91|0)[ -]?)?"
    r"(?:[6-9]\d{4}[ -]?\d{5}|[6-9]\d{9})"
    r"(?!\d)"
)
_PHONE_CONTEXT = re.compile(
    r"\b(?:phone|mobile|mob|cell|call|contact|whatsapp|number|no\.)\b"
    r"|फोन|मोबाइल",
    re.I,
)

_GSTIN_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]"
    r"(?![A-Za-z0-9])",
    re.I,
)
_GSTIN_STATE_CODES = frozenset(f"{n:02d}" for n in range(1, 39)) | {"97", "99"}
_GSTIN_CONTEXT = re.compile(r"\bgstin?\b|goods and services tax", re.I)
_BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

_IFSC_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])", re.I)
_IFSC_CONTEXT = re.compile(r"\bifsc\b|\bifs code\b|\bbank code\b", re.I)

# A UPI handle has no dot after the "@", which is what separates it from an email.
_UPI_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._-]{2,64}@[A-Za-z]{2,32}"
    r"(?![A-Za-z0-9-]|\.[A-Za-z0-9])"
)
_UPI_KNOWN_HANDLES = frozenset(
    {
        "upi", "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici",
        "paytm", "apl", "fbl", "sbi", "hdfcbank", "icici", "axisbank", "pnb",
        "boi", "cnrb", "kotak", "idfcbank", "indus", "yesbank", "airtel",
        "jio", "postbank", "freecharge",
    }
)
_UPI_CONTEXT = re.compile(r"\bupi\b|\bvpa\b|\bgpay\b|\bphonepe\b|\bpaytm\b", re.I)

_CONTEXT_WINDOW = 40


def _near(pattern: re.Pattern[str], text: str, start: int, end: int) -> bool:
    lo = max(0, start - _CONTEXT_WINDOW)
    return pattern.search(text, lo, min(len(text), end + _CONTEXT_WINDOW)) is not None


def _finding(category: str, type_: str, m: re.Match[str], confidence: float, detector: str) -> Finding:
    return Finding(
        category=category,
        type=type_,
        start=m.start(),
        end=m.end(),
        confidence=confidence,
        detector=detector,
    )


def detect_aadhaar(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _AADHAAR_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if not verhoeff_valid(digits):
            continue
        confidence = 0.95 if _near(_AADHAAR_CONTEXT, text, m.start(), m.end()) else 0.75
        findings.append(_finding("PII", "AADHAAR", m, confidence, "regex+verhoeff"))
    return findings


def detect_pan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _PAN_RE.finditer(text):
        value = m.group()
        if value[3].upper() not in _PAN_HOLDER_TYPES:
            continue
        confidence = 0.85 if value.isupper() else 0.6
        if _near(_PAN_CONTEXT, text, m.start(), m.end()):
            confidence = min(1.0, confidence + 0.1)
        findings.append(_finding("PII", "PAN", m, confidence, "regex"))
    return findings


def detect_phone(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())

        # A 12-digit run that passes the Aadhaar checksum is an Aadhaar, not a phone.
        if len(digits) == 12 and verhoeff_valid(digits):
            continue

        has_prefix = len(digits) > 10
        before_start = max(0, m.start() - _CONTEXT_WINDOW)
        if _PHONE_CONTEXT.search(text, before_start, m.start()):
            confidence = 0.95
        elif has_prefix:
            confidence = 0.85
        else:
            confidence = 0.6
        findings.append(_finding("PII", "PHONE", m, confidence, "regex"))
    return findings


def gstin_check_char(first_14: str) -> str:
    total = 0
    for i, ch in enumerate(first_14.upper()):
        product = _BASE36.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    return _BASE36[(36 - total % 36) % 36]


def detect_gstin(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _GSTIN_RE.finditer(text):
        value = m.group().upper()
        if value[:2] not in _GSTIN_STATE_CODES:
            continue
        if gstin_check_char(value[:14]) != value[14]:
            continue
        confidence = 0.95 if _near(_GSTIN_CONTEXT, text, m.start(), m.end()) else 0.9
        findings.append(_finding("FINANCIAL", "GSTIN", m, confidence, "regex+checksum"))
    return findings


def detect_ifsc(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _IFSC_RE.finditer(text):
        confidence = 0.7 if m.group().isupper() else 0.5
        if _near(_IFSC_CONTEXT, text, m.start(), m.end()):
            confidence = 0.95
        findings.append(_finding("FINANCIAL", "IFSC", m, confidence, "regex"))
    return findings


def detect_upi(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _UPI_RE.finditer(text):
        handle = m.group().rsplit("@", 1)[1].lower()
        confidence = 0.9 if handle in _UPI_KNOWN_HANDLES else 0.55
        if _near(_UPI_CONTEXT, text, m.start(), m.end()):
            confidence = max(confidence, 0.95)
        findings.append(_finding("FINANCIAL", "UPI", m, confidence, "regex"))
    return findings


def detect_india_pii(text: str) -> list[Finding]:
    upi = detect_upi(text)
    # A phone number used as a UPI id (9876543210@ybl) is one finding, not two.
    phones = [
        f
        for f in detect_phone(text)
        if not any(u.start <= f.start and f.end <= u.end for u in upi)
    ]
    found = (
        detect_aadhaar(text)
        + detect_pan(text)
        + phones
        + detect_gstin(text)
        + detect_ifsc(text)
        + upi
    )
    return sorted(found, key=lambda f: (f.start, f.end))
