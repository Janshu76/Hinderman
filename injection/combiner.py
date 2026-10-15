"""Fuse rule hits and the classifier score into one InjectionResult."""
from __future__ import annotations

from contracts import Finding, InjectionResult   # adjust the import to wherever contracts.py lives

from . import config
from .rules import RuleHit, noisy_or


def _type_for(rule_type: str, source: str) -> str:
    # Anything found inside a retrieved document is reported as INDIRECT_INJECTION.
    return config.DOCUMENT_TYPE if source == "document" else rule_type


def combine(hits: list[RuleHit], model_score: float | None, source: str, mode: str) -> InjectionResult:
    use_rules = mode in ("rules", "combined")
    wants_model = mode in ("model", "combined")
    rule_hits = hits if use_rules else []
    ms = model_score if (wants_model and model_score is not None) else None

    rule_score = noisy_or(h.weight for h in rule_hits)
    final = min(max(rule_score, ms if ms is not None else 0.0), 1.0)

    reasons = [f"{h.rule_id}: {h.description}" for h in rule_hits]
    if ms is not None:
        reasons.append(f"classifier score {ms:.2f}")
    elif wants_model:
        reasons.append("classifier unavailable" + (", rules only" if mode == "combined" else ""))

    # One finding per attack type, with the confidence the policy engine will read.
    by_type: dict[str, list[float]] = {}
    for h in rule_hits:
        by_type.setdefault(_type_for(h.type, source), []).append(h.weight)
    conf = {t: noisy_or(ws) for t, ws in by_type.items()}

    model_contributes = ms is not None and ms >= config.MIN_FINDING_CONFIDENCE
    if model_contributes:
        if conf:
            conf = {t: max(c, ms) for t, c in conf.items()}
        else:                                     # the model alone flagged it: no rule gave a type
            conf = {_type_for(config.DEFAULT_USER_TYPE, source): ms}

    if model_contributes and not rule_hits:
        detector = "model"
    elif model_contributes:
        detector = "rules+model"
    else:
        detector = "rules"

    findings = sorted(
        (Finding(category="INJECTION", type=t, confidence=round(min(c, 1.0), 4), detector=detector)
         for t, c in conf.items() if c >= config.MIN_FINDING_CONFIDENCE),
        key=lambda f: -f.confidence,
    )

    fields = {
        "score": round(final, 4),
        "label": "injection" if final >= config.LABEL_THRESHOLD else "benign",
        "reasons": reasons,
    }
    if "findings" in InjectionResult.model_fields:   # only after the team adds the field
        fields["findings"] = findings
    return InjectionResult(**fields)