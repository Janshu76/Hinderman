"""Credential detectors: API keys, passwords and high-entropy secrets."""
import math
import re

from contracts.schemas import Finding

_PREFIX_PATTERNS = [
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9-])xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{16,}")),
    ("SECRET", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "SECRET",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    ),
]

_KEY_CONTEXT_RE = re.compile(
    r"\b(?:api[_ -]?key|apikey|access[_ -]?key|secret[_ -]?key|client[_ -]?secret"
    r"|auth[_ -]?token|access[_ -]?token|token|secret)\b"
    r"(?:[ \t]*[:=][ \t]*|[ \t]+(?:is|hai)[ \t]+)"
    r"[\"']?(?P<value>[A-Za-z0-9_\-+/=.]{16,})",
    re.I,
)
_BEARER_RE = re.compile(r"\bbearer[ \t]+(?P<value>[A-Za-z0-9_\-+/=.]{20,})", re.I)

_PASSWORD_RE = re.compile(
    r"\b(?:password|passwd|pwd|passcode|passphrase|पासवर्ड)\b"
    r"(?:[ \t]*[:=][ \t]*|[ \t]+(?:is|hai|was)[ \t]+)"
    r"[\"']?(?P<value>[^\s\"',;]{4,64})",
    re.I,
)
_PASSWORD_STOPWORDS = frozenset(
    {
        "required", "incorrect", "wrong", "invalid", "expired", "short", "weak", "strong",
        "missing", "empty", "correct", "same", "reset", "changed", "valid", "hidden",
        "saved", "stored", "never", "always", "case-sensitive", "mandatory", "optional",
        "encrypted", "hashed", "none", "null", "unknown", "secure", "safe", "this",
        "that", "your", "mine", "yours", "set", "not", "being", "used", "given",
        "change", "update", "enter", "here", "below", "above", "click", "type", "please", "now",
    }
)

_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{24,}(?![A-Za-z0-9_+=-])")
_ENTROPY_THRESHOLD = 4.0

_PLACEHOLDER_PARTS = ("your", "example", "placeholder", "changeme", "xxxx", "****", "dummy", "sample", "<", "{{")

_PRIORITY = {"prefix": 0, "context": 1, "password": 2, "entropy": 3}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    v = value.lower()
    if re.fullmatch(r"[x*#._\-]+", v) or len(set(v)) <= 2:
        return True
    return v.startswith(("<", "{", "$", "%")) or any(p in v for p in _PLACEHOLDER_PARTS)


def _candidates(text: str) -> list[tuple[int, int, int, str, float, str]]:
    """(priority, start, end, type, confidence, detector)"""
    out = []

    for type_, pattern in _PREFIX_PATTERNS:
        for m in pattern.finditer(text):
            out.append((_PRIORITY["prefix"], m.start(), m.end(), type_, 0.97, "credentials:prefix"))

    for pattern in (_KEY_CONTEXT_RE, _BEARER_RE):
        for m in pattern.finditer(text):
            value = m.group("value")
            if _is_placeholder(value) or not re.search(r"\d", value):
                continue
            out.append((_PRIORITY["context"], m.start("value"), m.end("value"), "API_KEY", 0.85, "credentials:context"))

    for m in _PASSWORD_RE.finditer(text):
        value = m.group("value").rstrip(".!?)")
        if len(value) < 4 or _is_placeholder(value) or value.lower() in _PASSWORD_STOPWORDS:
            continue
        has_digit_or_symbol = bool(re.search(r"[\d\W_]", value))
        confidence = 0.9 if has_digit_or_symbol else 0.6
        start = m.start("value")
        out.append((_PRIORITY["password"], start, start + len(value), "PASSWORD", confidence, "credentials:password"))

    for m in _ENTROPY_RE.finditer(text):
        value = m.group()
        if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
            continue
        if _is_placeholder(value) or shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        out.append((_PRIORITY["entropy"], m.start(), m.end(), "SECRET", 0.6, "credentials:entropy"))

    return out


def detect_credentials(text: str) -> list[Finding]:
    ranked = sorted(_candidates(text), key=lambda c: (c[0], -c[4], c[1]))
    kept: list[tuple[int, int, int, str, float, str]] = []
    for cand in ranked:
        if any(cand[1] < k[2] and k[1] < cand[2] for k in kept):
            continue
        kept.append(cand)
    return [
        Finding(
            category="CREDENTIAL",
            type=type_,
            start=start,
            end=end,
            confidence=confidence,
            detector=detector,
        )
        for _, start, end, type_, confidence, detector in sorted(kept, key=lambda c: (c[1], c[2]))
    ]
