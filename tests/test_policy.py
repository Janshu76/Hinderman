from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import os

import pytest

from warden.models import Action, Finding, PolicyDocument, PolicyRule, Severity
from warden.policies import PolicyEngine, PolicyFileError, PolicyStore


def finding(
    category: str = "email", severity: Severity = Severity.MEDIUM
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        detector="test",
        message="test finding",
        matched_text="person@example.com",
        message_index=0,
    )


def policies(*rules: PolicyRule) -> PolicyDocument:
    return PolicyDocument(rules=list(rules))


def rule(
    action: Action = Action.WARN,
    category: str = "email",
    min_severity: Severity = Severity.LOW,
    priority: int = 0,
    enabled: bool = True,
) -> PolicyRule:
    return PolicyRule(
        action=action,
        category=category,
        min_severity=min_severity,
        priority=priority,
        enabled=enabled,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.LOW, Action.WARN),
        (Severity.MEDIUM, Action.WARN),
        (Severity.HIGH, Action.WARN),
        (Severity.CRITICAL, Action.WARN),
    ],
)
def test_matching_rule_applies_at_or_above_minimum(severity, expected):
    decision = PolicyEngine().evaluate([finding(severity=severity)], policies(rule()))
    assert decision.action == expected


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (Action.ALLOW, Action.ALLOW),
        (Action.WARN, Action.WARN),
        (Action.MASK, Action.MASK),
        (Action.REDACT, Action.REDACT),
        (Action.BLOCK, Action.BLOCK),
    ],
)
def test_each_policy_action_is_supported(action, expected):
    decision = PolicyEngine().evaluate([finding()], policies(rule(action=action)))
    assert decision.action == expected


@pytest.mark.parametrize(
    ("finding_severity", "minimum", "expected"),
    [
        (Severity.LOW, Severity.MEDIUM, Action.ALLOW),
        (Severity.MEDIUM, Severity.HIGH, Action.ALLOW),
        (Severity.HIGH, Severity.CRITICAL, Action.ALLOW),
    ],
)
def test_below_minimum_severity_does_not_match(finding_severity, minimum, expected):
    decision = PolicyEngine().evaluate(
        [finding(severity=finding_severity)],
        policies(rule(min_severity=minimum)),
    )
    assert decision.action == expected


def test_no_findings_allows_request():
    assert PolicyEngine().evaluate([], policies(rule())).action == Action.ALLOW


def test_non_matching_category_allows_request():
    decision = PolicyEngine().evaluate([finding()], policies(rule(category="other")))
    assert decision.action == Action.ALLOW


def test_disabled_rule_is_ignored():
    decision = PolicyEngine().evaluate([finding()], policies(rule(enabled=False)))
    assert decision.action == Action.ALLOW


def test_wildcard_category_matches():
    decision = PolicyEngine().evaluate([finding()], policies(rule(category="*")))
    assert decision.action == Action.WARN


def test_higher_severity_beats_higher_priority():
    rules = policies(
        rule(action=Action.BLOCK, category="other", priority=1000),
        rule(action=Action.WARN, category="email", priority=0),
    )
    decision = PolicyEngine().evaluate(
        [finding("other", Severity.LOW), finding("email", Severity.CRITICAL)], rules
    )
    assert decision.action == Action.WARN


def test_priority_breaks_ties_between_severities():
    rules = policies(
        rule(action=Action.WARN, priority=1),
        rule(action=Action.BLOCK, priority=2),
    )
    assert PolicyEngine().evaluate([finding()], rules).action == Action.BLOCK


def test_action_order_breaks_remaining_ties():
    rules = policies(rule(action=Action.WARN), rule(action=Action.BLOCK))
    assert PolicyEngine().evaluate([finding()], rules).action == Action.BLOCK


def test_selected_action_includes_all_policy_matched_findings():
    email = finding("email")
    other = finding("other", Severity.LOW)
    rules = policies(
        rule(action=Action.MASK, category="email"),
        rule(action=Action.BLOCK, category="other"),
    )
    decision = PolicyEngine().evaluate([email, other], rules)
    assert decision.action == Action.MASK
    assert decision.findings == [email, other]


def test_policy_store_loads_and_returns_independent_copy(tmp_path: Path):
    store = PolicyStore(Path(__file__).parents[1] / "config" / "policies.yaml")
    original = store.get()
    original.rules.clear()
    assert store.get().rules


def test_policy_store_detects_external_file_edit(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    original_stat = path.stat()
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: warn \n",
        encoding="utf-8",
    )
    assert path.stat().st_size == original_stat.st_size
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    assert store.get().rules[0].action == Action.WARN


def test_policy_store_put_persists_and_reloads(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    updated = policies(rule(action=Action.REDACT))
    store.put(updated)
    assert store.get().rules[0].action == Action.REDACT
    assert "redact" in path.read_text(encoding="utf-8")


def test_policy_store_reports_invalid_yaml(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text("rules: [", encoding="utf-8")
    with pytest.raises(PolicyFileError, match="Cannot load policies"):
        PolicyStore(path)


def test_policy_store_reports_invalid_policy_shape(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text("version: 1\nrules: []\n", encoding="utf-8")
    with pytest.raises(PolicyFileError, match="Cannot load policies"):
        PolicyStore(path)


def test_policy_store_reports_missing_file(tmp_path: Path):
    with pytest.raises(PolicyFileError, match="Cannot load policies"):
        PolicyStore(tmp_path / "missing.yaml")


def test_policy_store_reports_file_removed_after_startup(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    path.unlink()
    with pytest.raises(PolicyFileError, match="Cannot read policies"):
        store.get()


def test_invalid_external_edit_is_reported_without_silent_fallback(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    path.write_text("rules: [", encoding="utf-8")
    with pytest.raises(PolicyFileError, match="Cannot load policies"):
        store.get()


def test_concurrent_policy_reads_and_atomic_writes_remain_valid(tmp_path: Path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    documents = [
        policies(rule(action=action))
        for action in (Action.BLOCK, Action.WARN, Action.REDACT, Action.MASK)
    ]

    def write_and_read(index: int):
        for offset in range(20):
            store.put(documents[(index + offset) % len(documents)])
            assert store.get().rules[0].action in set(Action)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write_and_read, range(4)))
    assert not list(tmp_path.glob("*.tmp"))


def test_policy_store_reports_atomic_replace_failure(tmp_path: Path, monkeypatch):
    path = tmp_path / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)

    def fail_replace(source, destination):
        raise OSError("replacement failed")

    monkeypatch.setattr("warden.policies.os.replace", fail_replace)
    with pytest.raises(PolicyFileError, match="Cannot save policies"):
        store.put(policies(rule(action=Action.WARN)))
    assert path.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_policy_store_reports_failure_before_temporary_file_creation(tmp_path: Path):
    parent = tmp_path / "policy-directory"
    parent.mkdir()
    path = parent / "policies.yaml"
    path.write_text(
        "version: 1\nrules:\n  - category: email\n    action: block\n",
        encoding="utf-8",
    )
    store = PolicyStore(path)
    path.unlink()
    parent.rmdir()
    parent.write_text("not a directory", encoding="utf-8")

    with pytest.raises(PolicyFileError, match="Cannot save policies"):
        store.put(policies(rule(action=Action.WARN)))


@pytest.mark.parametrize("bad_value", ["invalid", None, 0, [], {}])
def test_policy_schema_rejects_invalid_yaml_documents(tmp_path: Path, bad_value):
    path = tmp_path / "policies.yaml"
    import yaml

    path.write_text(yaml.safe_dump(bad_value), encoding="utf-8")
    with pytest.raises(PolicyFileError, match="Cannot load policies"):
        PolicyStore(path)
