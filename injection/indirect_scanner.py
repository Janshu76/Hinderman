from __future__ import annotations

import re


def scan_indirect_injection(text: str) -> dict:
    """Look for hidden instruction patterns in retrieved documents or chunks."""
    normalized = (text or "").lower()
    score = 0.0
    reasons: list[str] = []

    patterns = [
        ("html comment", r"<!--.*?-->", 0.7),
        ("hidden text", r"display\s*:\s*none|visibility\s*:\s*hidden", 0.6),
        ("assistant instruction", r"assistant\s*,\s*do\s+", 0.9),
        ("prompt injection", r"ignore\s+(previous|all)\s+(instructions|rules)", 0.95),
        ("system prompt leak", r"reveal\s+(your\s+)?system\s+prompt", 0.98),
        ("base64 or hex gibberish", r"(?:base64|hex|rot13|cipher)\s*[:=]", 0.45),
    ]

    for name, pattern, weight in patterns:
        if re.search(pattern, normalized):
            score += weight
            reasons.append(name)

    score = min(1.0, round(score, 4))
    label = "malicious" if score >= 0.8 else "suspicious" if score >= 0.5 else "benign"
    return {"score": score, "label": label, "reasons": reasons}


def scan_document(text: str) -> dict:
    return scan_indirect_injection(text)
