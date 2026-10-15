import hashlib
import os
import tempfile
import threading
from pathlib import Path

import yaml
from pydantic import ValidationError

from warden.models import Action, Finding, PolicyDocument, PolicyRule, Severity


class PolicyFileError(RuntimeError):
    """A policy file could not be loaded or saved safely."""


class PolicyDecision:
    def __init__(
        self,
        action: Action,
        reason: str,
        findings: list[Finding],
        replacement: str = "[REDACTED]",
    ) -> None:
        self.action = action
        self.reason = reason
        self.findings = findings
        self.replacement = replacement


SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

ACTION_ORDER = {
    Action.ALLOW: 0,
    Action.WARN: 1,
    Action.MASK: 2,
    Action.REDACT: 3,
    Action.BLOCK: 4,
}


class PolicyEngine:
    def evaluate(
        self, findings: list[Finding], policies: PolicyDocument
    ) -> PolicyDecision:
        candidates: list[tuple[tuple[int, int, int], PolicyRule, Finding]] = []
        for finding in findings:
            for rule in policies.rules:
                if not rule.enabled:
                    continue
                if rule.category not in {"*", finding.category}:
                    continue
                if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[rule.min_severity]:
                    continue
                rank = (
                    SEVERITY_ORDER[finding.severity],
                    rule.priority,
                    ACTION_ORDER[rule.action],
                )
                candidates.append((rank, rule, finding))

        if not candidates:
            return PolicyDecision(Action.ALLOW, "No policy matched the findings.", [])

        _, selected_rule, selected_finding = max(candidates, key=lambda item: item[0])
        applicable_findings: list[Finding] = []
        seen_findings: set[int] = set()
        for _, _, finding in candidates:
            if id(finding) not in seen_findings:
                applicable_findings.append(finding)
                seen_findings.add(id(finding))
        return PolicyDecision(
            action=selected_rule.action,
            reason=(
                f"Policy for '{selected_rule.category}' matched a "
                f"{selected_finding.severity.value} finding."
            ),
            findings=applicable_findings,
            replacement=selected_rule.replacement,
        )


class PolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._document: PolicyDocument | None = None
        self._content_digest: str | None = None
        self._reload_locked()

    def get(self) -> PolicyDocument:
        with self._lock:
            try:
                content = self.path.read_bytes()
            except OSError as exc:
                raise PolicyFileError(f"Cannot read policies at {self.path}: {exc}") from exc
            digest = hashlib.sha256(content).hexdigest()
            if digest != self._content_digest:
                self._load_content_locked(content)
            assert self._document is not None
            return self._document.model_copy(deep=True)

    def put(self, document: PolicyDocument) -> PolicyDocument:
        serialized = yaml.safe_dump(
            document.model_dump(mode="json"), sort_keys=False, allow_unicode=True
        )
        with self._lock:
            temporary_path: Path | None = None
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self.path.parent,
                    prefix=f".{self.path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary:
                    temporary.write(serialized)
                    temporary_path = Path(temporary.name)
                os.replace(temporary_path, self.path)
                self._document = document.model_copy(deep=True)
                self._content_digest = hashlib.sha256(
                    serialized.encode("utf-8")
                ).hexdigest()
            except OSError as exc:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
                raise PolicyFileError(f"Cannot save policies at {self.path}: {exc}") from exc
            return document.model_copy(deep=True)

    def _reload_locked(self) -> None:
        try:
            content = self.path.read_bytes()
        except OSError as exc:
            raise PolicyFileError(f"Cannot load policies at {self.path}: {exc}") from exc
        self._load_content_locked(content)

    def _load_content_locked(self, content: bytes) -> None:
        try:
            raw = yaml.safe_load(content.decode("utf-8"))
            document = PolicyDocument.model_validate(raw)
        except (UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise PolicyFileError(f"Cannot load policies at {self.path}: {exc}") from exc
        self._document = document
        self._content_digest = hashlib.sha256(content).hexdigest()
