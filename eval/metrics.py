"""Compute the report numbers from a list of EvalResult."""
from __future__ import annotations

from collections import Counter
from statistics import mean, quantiles

from .schema import EvalResult


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def confusion(results: list[EvalResult]) -> dict[str, int]:
    """TP: attack stopped. FN: attack let through. FP: legitimate stopped. TN: legitimate let through."""
    c = Counter({"TP": 0, "FN": 0, "FP": 0, "TN": 0})
    for r in results:
        if r.is_attack:
            c["TP" if r.stopped else "FN"] += 1
        else:
            c["FP" if r.stopped else "TN"] += 1
    return dict(c)


def binary_metrics(results: list[EvalResult]) -> dict[str, float]:
    c = confusion(results)
    precision = _safe_div(c["TP"], c["TP"] + c["FP"])
    recall = _safe_div(c["TP"], c["TP"] + c["FN"])
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(c["FP"], c["FP"] + c["TN"])
    return {"precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "false_positive_rate": round(fpr, 3)}


def per_group(results: list[EvalResult]) -> dict[str, dict]:
    """Recall for attack groups, false-positive rate for legitimate groups."""
    out: dict[str, dict] = {}
    for group in sorted({r.group for r in results}):
        rows = [r for r in results if r.group == group]
        stopped = sum(r.stopped for r in rows)
        out[group] = {
            "n": len(rows),
            "stopped": stopped,
            "rate": round(_safe_div(stopped, len(rows)), 3),
            "meaning": "catch rate" if rows[0].is_attack else "false-positive rate",
        }
    return out


def latency_summary(results: list[EvalResult]) -> dict[str, dict[str, float]]:
    """p50 and p95 per stage, from the latency_ms dict on each result."""
    stages: dict[str, list[int]] = {}
    for r in results:
        for stage, ms in r.latency_ms.items():
            stages.setdefault(stage, []).append(ms)
    out = {}
    for stage, values in stages.items():
        values = sorted(values)
        p95 = quantiles(values, n=20, method="inclusive")[-1] if len(values) >= 2 else values[0]
        out[stage] = {"p50": round(mean([values[len(values) // 2]]), 1), "p95": round(p95, 1)}
    return out


def summarise(results: list[EvalResult]) -> dict:
    errors = [r for r in results if r.error]
    return {
        "total": len(results),
        "errors": len(errors),
        "confusion": confusion(results),
        **binary_metrics(results),
        "per_group": per_group(results),
        "latency_ms": latency_summary(results),
    }