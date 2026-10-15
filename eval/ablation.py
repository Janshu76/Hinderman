"""Ablation: rules only vs model only vs combined. Calls injection.score() directly, no gateway."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from injection import config as inj_config
from injection import scorer

from .metrics import binary_metrics, confusion
from .schema import EvalCase, EvalResult

DATASET = Path(__file__).parent / "dataset.jsonl"
MODES = ["rules", "model", "combined"]


def load_cases(path: Path = DATASET, split: str = "dev") -> list[EvalCase]:
    cases: list[EvalCase] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            if {"text", "label", "source"} <= data.keys():
                malicious = data["label"] == "malicious"
                source = data["source"]
                if data["label"] not in {"benign", "malicious"}:
                    raise ValueError(f"unsupported legacy label {data['label']!r}")
                if source not in {"user", "document"}:
                    raise ValueError(f"unsupported legacy source {source!r}")
                indirect = malicious and source == "document"
                data = {
                    "id": f"legacy-{lineno:04d}",
                    "group": (
                        "injection_indirect" if indirect
                        else "injection_direct" if malicious
                        else "legit"
                    ),
                    "prompt": data["text"],
                    "document_text": data["text"] if source == "document" else None,
                    "expected_action": "block" if malicious else "allow",
                }
            case = EvalCase(**data)
        except Exception as exc:
            raise ValueError(f"{path.name} line {lineno}: {exc}") from exc
        if case.split == split:
            cases.append(case)
    return cases


def _score_case(case: EvalCase, mode: str) -> EvalResult:
    os.environ["INJECTION_MODE"] = mode                 # read at call time by injection.config
    source = "document" if case.group == "injection_indirect" else "user"
    text = case.document_text or case.prompt
    start = time.perf_counter()
    result = scorer.score(text, source)
    ms = int((time.perf_counter() - start) * 1000)
    stopped = result.score >= inj_config.BLOCK_THRESHOLD      # block-level only, like INJ-001
    found = sorted({f.type for f in result.findings})
    return EvalResult(
        case_id=case.id, group=case.group, is_attack=case.is_attack,
        action_taken="block" if stopped else "allow",
        found_types=found, stopped=stopped,
        correct=stopped if case.is_attack else not stopped,
        latency_ms={"injection": ms},
    )


def run_ablation(split: str = "dev") -> dict[str, dict]:
    cases = load_cases(split=split)
    report: dict[str, dict] = {}
    try:
        for mode in MODES:
            results = [_score_case(c, mode) for c in cases]
            report[mode] = {**binary_metrics(results), "confusion": confusion(results)}
    finally:
        os.environ.pop("INJECTION_MODE", None)
    return report


if __name__ == "__main__":
    print(json.dumps(run_ablation(), indent=2))