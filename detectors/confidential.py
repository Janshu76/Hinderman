"""Confidential-content detectors: classification markers and source code."""
import re

from contracts.schemas import Finding

_PHRASES = re.compile(
    r"\b(?:strictly confidential|company confidential|confidential and proprietary"
    r"|proprietary and confidential|internal use only|for internal use only"
    r"|not for (?:external )?distribution|do not distribute)\b",
    re.I,
)
# Upper-case only, so a normal sentence such as "what does confidential mean" is not flagged.
_UPPER_MARKERS = re.compile(
    r"\b(?:CONFIDENTIAL|TOP SECRET|TRADE SECRET|PROPRIETARY|INTERNAL USE ONLY"
    r"|DO NOT (?:SHARE|FORWARD|DISTRIBUTE))\b"
)

_STRONG_LINE = [
    re.compile(p)
    for p in (
        r"^\s*(?:async\s+)?def\s+\w+\s*\(.*\)\s*(?:->\s*[^:]+)?:",
        r"^\s*(?:async\s+)?(?:class|interface|struct|enum)\s+\w+.*[:{]\s*$",
        r"^\s*import\s+[\w.*]+(?:\s+as\s+\w+)?\s*;?\s*$",
        r"^\s*from\s+[\w.]+\s+import\s+[\w*, ()]+\s*$",
        r"^\s*import\s+.+\s+from\s+['\"].+['\"]\s*;?\s*$",
        r"^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=",
        r"^\s*(?:export\s+)?(?:async\s+)?function\s*\w*\s*\(",
        r"^\s*(?:public|private|protected|static)\s+[\w<>\[\], .]+\(.*\)\s*(?:throws\s+\w+\s*)?\{?\s*$",
        r"^\s*#include\s*[<\"]",
        r"^\s*(?:if|for|while|switch)\s*\(.*\)\s*\{?\s*$",
        r"^\s*(?:elif\s.*|else|try|except\b.*|finally)\s*:\s*$",
        r"^\s*(?:return|raise|throw)\b[^.!?]*;\s*$",
        r"^\s*[\w.\[\]\"']+\s*[-+*/]?=\s*[^=].*;\s*$",
        r"^\s*(?:SELECT\s.+\sFROM\s|INSERT\s+INTO\s|CREATE\s+TABLE\s|DELETE\s+FROM\s|UPDATE\s+\w+\s+SET\s)",
        r"^\s*\w[\w.]*\(.*\)\s*;\s*$",
        r"^\s*(?:print|console\.log|System\.out\.println)\(.*\)",
    )
]
_WEAK_LINE = [
    re.compile(p)
    for p in (
        r"^\s*$",
        r"^\s*[}\])]+[;,]?\s*$",
        r"^\s*```",
        r"^(?:\s{2,}|\t)\S",
        r"^\s*//",
        r"^\s*@\w+",
    )
]


def detect_confidential_markers(text: str) -> list[Finding]:
    spans: list[tuple[int, int, float]] = []
    for m in _PHRASES.finditer(text):
        spans.append((m.start(), m.end(), 0.85))
    for m in _UPPER_MARKERS.finditer(text):
        if not any(m.start() < e and s < m.end() for s, e, _ in spans):
            spans.append((m.start(), m.end(), 0.7))
    return [
        Finding(
            category="CONFIDENTIAL",
            type="CONFIDENTIAL_TEXT",
            start=s,
            end=e,
            confidence=c,
            detector="confidential:marker",
        )
        for s, e, c in sorted(spans)
    ]


def _line_kind(line: str) -> str:
    body = line.rstrip("\r\n")
    if any(p.match(body) for p in _STRONG_LINE):
        return "strong"
    if any(p.match(body) for p in _WEAK_LINE):
        return "weak"
    return "other"


def detect_source_code(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines(keepends=True)
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)

    block: list[int] = []
    strong = 0
    inner = 0
    has_fence = False
    fence_lang = False

    def finish() -> None:
        nonlocal block, strong, inner, has_fence, fence_lang
        content = [i for i in block if lines[i].strip()]
        is_code = strong >= 3 or (has_fence and strong >= 1) or (fence_lang and inner >= 1)
        if content and is_code:
            first, last = content[0], content[-1]
            start = offsets[first] + (len(lines[first]) - len(lines[first].lstrip()))
            end = offsets[last] + len(lines[last].rstrip())
            confidence = 0.9 if strong >= 6 else 0.8 if strong >= 3 else 0.75
            findings.append(
                Finding(
                    category="CONFIDENTIAL",
                    type="SOURCE_CODE",
                    start=start,
                    end=end,
                    confidence=confidence,
                    detector="confidential:code",
                )
            )
        block, strong, inner, has_fence, fence_lang = [], 0, 0, False, False

    in_fence = False
    for i, line in enumerate(lines):
        kind = _line_kind(line)
        if kind == "other" and in_fence:
            kind = "weak"
        if kind == "other":
            finish()
            continue
        block.append(i)
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            has_fence = True
            if re.match(r"```\w", stripped):
                fence_lang = True
        elif stripped:
            inner += 1
            if kind == "strong":
                strong += 1
    finish()
    return findings


def detect_confidential(text: str) -> list[Finding]:
    return sorted(
        detect_confidential_markers(text) + detect_source_code(text),
        key=lambda f: (f.start, f.end),
    )
