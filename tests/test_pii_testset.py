import json
from pathlib import Path

from detectors.india_pii import detect_india_pii


_DATA_PATH = Path(__file__).parent / "data" / "pii_testset.json"


def test_pii_testset_labels_match_india_detectors():
    dataset = json.loads(_DATA_PATH.read_text(encoding="utf-8"))

    assert len(dataset["cases"]) == 40
    assert len({case["id"] for case in dataset["cases"]}) == 40

    for case in dataset["cases"]:
        findings = detect_india_pii(case["text"])
        assert [finding.type for finding in findings] == case["expected_types"], case["id"]
