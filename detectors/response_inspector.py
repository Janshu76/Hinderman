"""Response inspector: the same detectors on model output, plus optional leak checks."""
import re

from contracts.schemas import Finding

from .inspector import inspect

_SHINGLE = 6


def _words(text: str) -> list[tuple[int, int, str]]:
    out = []
    for m in re.finditer(r"\S+", text):
        norm = re.sub(r"\W+", "", m.group().lower())
        if norm:
            out.append((m.start(), m.end(), norm))
    return out


def detect_canary(text: str, canary: str) -> list[Finding]:
    if not canary:
        return []
    return [
        Finding(
            category="INJECTION",
            type="CANARY_LEAK",
            start=m.start(),
            end=m.end(),
            confidence=0.99,
            detector="canary",
        )
        for m in re.finditer(re.escape(canary), text)
    ]


def detect_prompt_leak(text: str, system_prompt: str, min_words: int = 10) -> list[Finding]:
    """Flag stretches of the response that repeat the system prompt word for word."""
    prompt_words = [w for _, _, w in _words(system_prompt)]
    if len(prompt_words) < _SHINGLE:
        return []
    shingles = {tuple(prompt_words[i:i + _SHINGLE]) for i in range(len(prompt_words) - _SHINGLE + 1)}

    resp = _words(text)
    matched = [False] * len(resp)
    for i in range(len(resp) - _SHINGLE + 1):
        if tuple(w for _, _, w in resp[i:i + _SHINGLE]) in shingles:
            for j in range(i, i + _SHINGLE):
                matched[j] = True

    findings: list[Finding] = []
    i = 0
    while i < len(resp):
        if not matched[i]:
            i += 1
            continue
        j = i
        while j + 1 < len(resp) and matched[j + 1]:
            j += 1
        length = j - i + 1
        if length >= min_words:
            findings.append(
                Finding(
                    category="INJECTION",
                    type="SYSTEM_PROMPT_EXTRACTION",
                    start=resp[i][0],
                    end=resp[j][1],
                    confidence=0.9 if length >= 20 else 0.75,
                    detector="prompt_leak",
                )
            )
        i = j + 1
    return findings


def inspect_response(text: str, ctx=None, *, system_prompt: str | None = None, canary: str | None = None) -> list[Finding]:
    findings = inspect(text, "response", ctx)
    if canary:
        findings += detect_canary(text, canary)
    if system_prompt:
        findings += detect_prompt_leak(text, system_prompt)
    return sorted(findings, key=lambda f: (f.start, f.end))
