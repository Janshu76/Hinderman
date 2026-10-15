"""Shared contracts for the AI Security Gateway (CC6-AI03)."""

import re
from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator, model_validator


Category = Literal[
    "PII",
    "FINANCIAL",
    "CREDENTIAL",
    "CONFIDENTIAL",
    "INJECTION",
    "RESTRICTED_DOC",
]
Direction = Literal["prompt", "response"]
Action = Literal["allow", "warn", "mask", "redact", "block", "require_approval"]
ApprovalStatus = Literal["pending", "approved", "rejected"]

MAX_PROMPT_CHARS = 100_000
GENESIS_HASH = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")

TYPE_CATEGORY: dict[str, Category] = {
    "AADHAAR": "PII",
    "PAN": "PII",
    "PHONE": "PII",
    "EMAIL": "PII",
    "PERSON": "PII",
    "GSTIN": "FINANCIAL",
    "IFSC": "FINANCIAL",
    "UPI": "FINANCIAL",
    "CARD": "FINANCIAL",
    "PASSWORD": "CREDENTIAL",
    "API_KEY": "CREDENTIAL",
    "SECRET": "CREDENTIAL",
    "CONFIDENTIAL_TEXT": "CONFIDENTIAL",
    "SOURCE_CODE": "CONFIDENTIAL",
    "SYSTEM_PROMPT_EXTRACTION": "INJECTION",
    "INSTRUCTION_OVERRIDE": "INJECTION",
    "DATA_EXFILTRATION": "INJECTION",
    "INDIRECT_INJECTION": "INJECTION",
    "CANARY_LEAK": "INJECTION",
    "RESTRICTED_DOCUMENT": "RESTRICTED_DOC",
}
KNOWN_TYPES: frozenset[str] = frozenset(TYPE_CATEGORY)


class Finding(BaseModel):
    category: Category
    type: str
    start: int | None = None
    end: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    detector: str = Field(min_length=1)

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in KNOWN_TYPES:
            raise ValueError(f"Unknown finding type: {value!r}")
        return value

    @model_validator(mode="after")
    def validate_finding(self) -> "Finding":
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must both be set or both be None")
        if self.start is not None and self.end is not None:
            if self.start < 0 or self.end <= self.start:
                raise ValueError("Expected 0 <= start < end")
        expected = TYPE_CATEGORY.get(self.type)
        if expected is not None and self.category != expected:
            raise ValueError(
                f"Finding type {self.type!r} requires category "
                f"{expected!r}, not {self.category!r}"
            )
        return self


class UserContext(BaseModel):
    user_id: str = Field(min_length=1)
    role: Literal["intern", "hr_officer", "finance_manager", "admin"]
    department: str = Field(min_length=1)
    clearance: int = Field(ge=0, le=3)


class InjectionResult(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    label: Literal["injection", "benign"]
    reasons: list[str] = Field(default_factory=list)


class Chunk(BaseModel):
    doc_id: str = Field(min_length=1)
    text: str
    score: float | None = None


class RetrievalResult(BaseModel):
    chunks: list[Chunk] = Field(default_factory=list)
    denied_count: int = Field(default=0, ge=0)
    denied_doc_ids: list[str] = Field(default_factory=list)


class AuditFinding(BaseModel):
    """A finding summary that never stores the matched text."""

    type: str
    count: int = Field(ge=1)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in KNOWN_TYPES:
            raise ValueError(f"Unknown finding type: {value!r}")
        return value


class AuditEvent(BaseModel):
    id: str | None = None
    request_id: str | None = Field(default=None, min_length=1, max_length=64)
    ts: datetime
    user_id: str = Field(min_length=1)
    direction: Direction
    findings: list[AuditFinding] = Field(default_factory=list)
    policy_id: str | None = None
    action: Action
    snippet_redacted: str = Field(max_length=500)
    content_sha256: str
    hmac_key_id: str = Field(default="k1", min_length=1, max_length=32)
    prev_hash: str
    latency_ms: int = Field(ge=0)
    denied_doc_ids: list[str] = Field(default_factory=list)

    @field_validator("ts")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Audit timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("content_sha256", "prev_hash")
    @classmethod
    def validate_hash_format(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("Expected exactly 64 lowercase hexadecimal characters")
        return value


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1)
    use_rag: bool = False

    @field_validator("prompt")
    @classmethod
    def reject_blank_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt cannot be blank")
        return value


class ChatResponse(BaseModel):
    response: str
    action_taken: Action
    findings_summary: list[AuditFinding] = Field(default_factory=list)
    request_id: str


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "rejected"]


class LoginRequest(BaseModel):
    model_config = {"extra": "forbid"}

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str = Field(min_length=1)
    token_type: Literal["bearer"] = "bearer"


class TokenResolutionRequest(BaseModel):
    model_config = {"extra": "forbid"}

    access_token: str = Field(min_length=1)


class ApprovalEnqueueRequest(BaseModel):
    model_config = {"extra": "forbid"}

    request_id: str = Field(min_length=1, max_length=64)
    findings: list[Finding]
    redacted_snippet: str = Field(max_length=500)


class ApprovalEnqueueResponse(BaseModel):
    approval_id: str = Field(min_length=1)


class AuditEventResponse(BaseModel):
    event_id: str = Field(min_length=1)


class Detectors(Protocol):
    """M2 detector interface called by M1."""

    def inspect(self, text: str, direction: Direction, ctx: UserContext) -> list[Finding]: ...


class InjectionScorer(Protocol):
    """M3 injection-scoring interface called by M1."""

    def score(
        self, text: str, source: Literal["user", "document"]
    ) -> InjectionResult: ...


class Retriever(Protocol):
    """M4 retrieval interface called by M1."""

    def retrieve(self, query: str, user: UserContext, k: int = 4) -> RetrievalResult: ...


@runtime_checkable
class PlatformServices(Protocol):
    """M2 platform services called by M1."""

    def get_current_user(self, token: str) -> UserContext: ...

    def log_event(self, event: AuditEvent) -> str:
        """Persist the event and return its ID."""
        ...

    def enqueue_approval(
        self, request_id: str, findings: list[Finding], redacted_snippet: str
    ) -> str:
        """Queue approval and return its ID."""
        ...

    def get_approval_status(self, approval_id: str) -> ApprovalStatus: ...
