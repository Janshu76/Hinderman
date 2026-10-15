import asyncio
import re
from collections.abc import Sequence
from threading import Lock
from typing import Protocol

from contracts import InjectionResult
from injection import score as score_injection
from injection.config import BLOCK_THRESHOLD
from warden.models import ChatMessage, Finding, Severity

_INJECTION_SCORER_LOCK = Lock()


class Detector(Protocol):
    name: str

    async def detect(
        self, user_id: str, messages: Sequence[ChatMessage]
    ) -> list[Finding]: ...


class StubAuthDetector:
    """Demo-only allowlist in place of the production authentication module."""

    name = "stub_auth"

    def __init__(self, allowed_users: frozenset[str] = frozenset({"demo"})) -> None:
        self._allowed_users = allowed_users

    async def detect(
        self, user_id: str, messages: Sequence[ChatMessage]
    ) -> list[Finding]:
        if user_id in self._allowed_users:
            return []
        return [
            Finding(
                category="auth_failure",
                severity=Severity.HIGH,
                detector=self.name,
                message="The demo authentication allowlist rejected this user.",
            )
        ]


class SensitiveDataDetector:
    """Demo detector for common sensitive values; replace with the production DLP module."""

    name = "stub_sensitive_data"
    _patterns = (
        (
            "email",
            re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        ),
        (
            "payment_card",
            re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        ),
    )

    async def detect(
        self, user_id: str, messages: Sequence[ChatMessage]
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Conversation roles come from the client, so every supplied message is untrusted.
        for index, message in enumerate(messages):
            for category, pattern in self._patterns:
                for match in pattern.finditer(message.content):
                    findings.append(
                        Finding(
                            category=category,
                            severity=Severity.MEDIUM,
                            detector=self.name,
                            message=f"Potential {category.replace('_', ' ')} detected.",
                            matched_text=match.group(),
                            message_index=index,
                        )
                    )
        return findings


class PromptInjectionDetector:
    """Small demo signature detector, not a substitute for a production classifier."""

    name = "stub_prompt_injection"
    _pattern = re.compile(
        r"\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions?|rules?)\b|reveal\s+(the\s+)?(system\s+)?prompt",
        re.IGNORECASE,
    )

    async def detect(
        self, user_id: str, messages: Sequence[ChatMessage]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for index, message in enumerate(messages):
            if self._pattern.search(message.content):
                findings.append(
                    Finding(
                        category="prompt_injection",
                        severity=Severity.HIGH,
                        detector=self.name,
                        message="A known prompt-injection phrase was detected.",
                        message_index=index,
                    )
                )
        return findings


class InjectionScorerDetector:
    """Adapt the shared injection scorer to WARDEN's detector interface."""

    name = "injection_scorer"

    async def detect(
        self, user_id: str, messages: Sequence[ChatMessage]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for index, message in enumerate(messages):
            result: InjectionResult = await asyncio.to_thread(
                self._score, message.content, "user"
            )
            findings.extend(self._findings(result, "user", index))
        return findings

    async def detect_documents(self, chunks: Sequence[str]) -> list[Finding]:
        findings: list[Finding] = []
        for text in chunks:
            result: InjectionResult = await asyncio.to_thread(
                self._score, text, "document"
            )
            findings.extend(self._findings(result, "document", None))
        return findings

    def _findings(
        self, result: InjectionResult, source: str, message_index: int | None
    ) -> list[Finding]:
        if result.label != "injection":
            return []

        injection_findings = result.findings or [None]
        return [
            Finding(
                category=(
                    "indirect_prompt_injection"
                    if source == "document"
                    else "prompt_injection"
                ),
                severity=(
                    Severity.HIGH
                    if result.score >= BLOCK_THRESHOLD
                    else Severity.MEDIUM
                ),
                detector=self.name,
                message=(
                    f"{'Retrieved document' if source == 'document' else 'Prompt'} "
                    f"injection signal "
                    f"{finding.type if finding is not None else 'injection'} "
                    f"detected with confidence "
                    f"{finding.confidence if finding is not None else result.score:.2f}."
                ),
                message_index=message_index,
            )
            for finding in injection_findings
        ]

    @staticmethod
    def _score(text: str, source: str = "user") -> InjectionResult:
        with _INJECTION_SCORER_LOCK:
            return score_injection(text, source)
