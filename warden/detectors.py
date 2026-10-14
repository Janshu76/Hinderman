import re
from collections.abc import Sequence
from typing import Protocol

from warden.models import ChatMessage, Finding, Severity


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
        ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
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
        re.I,
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
