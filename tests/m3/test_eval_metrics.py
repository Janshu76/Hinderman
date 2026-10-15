"""Metrics checked on a small case worked out by hand, plus the schema and dataset checks."""
import itertools

import pytest
from pydantic import ValidationError

from eval.ablation import load_cases
from eval.metrics import binary_metrics, confusion, latency_summary, per_group, summarise
from eval.schema import ATTACK_GROUPS, EvalCase, EvalResult

_ids = itertools.count()


def make(group, stopped, latency=None, error=None):
    attack = group in ATTACK_GROUPS
    return EvalResult(
        case_id=f"c{next(_ids)}",
        group=group,
        is_attack=attack,
        action_taken="block" if stopped else "allow",
        stopped=stopped,
        correct=stopped if attack else not stopped,
        latency_ms=latency or {},
        error=error,
    )


# 3 attacks: 2 caught, 1 missed.  4 legitimate: 1 wrongly stopped, 3 let through.
KNOWN = [
    make("injection_direct", True),
    make("injection_direct", True),
    make("injection_direct", False),
    make("legit", True),
    make("legit", False),
    make("legit", False),
    make("legit", False),
]


def test_confusion_counts_match_hand_count():
    assert confusion(KNOWN) == {"TP": 2, "FN": 1, "FP": 1, "TN": 3}


def test_precision_recall_f1_and_false_positive_rate():
    m = binary_metrics(KNOWN)
    assert m["precision"] == pytest.approx(0.667, abs=1e-3)   # 2 / 3
    assert m["recall"] == pytest.approx(0.667, abs=1e-3)      # 2 / 3
    assert m["f1"] == pytest.approx(0.667, abs=1e-3)
    assert m["false_positive_rate"] == pytest.approx(0.25)    # 1 / 4


def test_empty_results_do_not_divide_by_zero():
    assert binary_metrics([]) == {"precision": 0.0, "recall": 0.0, "f1": 0.0, "false_positive_rate": 0.0}


def test_per_group_uses_catch_rate_for_attacks_and_fpr_for_legit():
    groups = per_group(KNOWN)
    assert groups["injection_direct"]["meaning"] == "catch rate"
    assert groups["injection_direct"]["rate"] == pytest.approx(0.667, abs=1e-3)
    assert groups["legit"]["meaning"] == "false-positive rate"
    assert groups["legit"]["rate"] == pytest.approx(0.25)


def test_latency_p50_and_p95():
    results = [make("legit", False, latency={"total": ms}) for ms in (10, 20, 30, 40, 50)]
    stats = latency_summary(results)["total"]
    assert stats["p50"] == 30.0
    assert 40 <= stats["p95"] <= 50


def test_summary_counts_errors():
    assert summarise(KNOWN + [make("legit", False, error="timeout")])["errors"] == 1


def test_unknown_finding_type_is_rejected():
    with pytest.raises(ValidationError):
        EvalCase(id="x", group="legit", prompt="hi", expected_action="allow", expected_types=["MADE_UP"])


def test_is_attack_follows_the_group():
    assert EvalCase(id="a", group="injection_direct", prompt="x", expected_action="block").is_attack
    assert not EvalCase(id="b", group="legit", prompt="x", expected_action="allow").is_attack


def test_dataset_file_parses_and_ids_are_unique():
    cases = load_cases(split="dev")
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids))