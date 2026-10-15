"""
Shared contracts for the AI Security Gateway (CC6-AI03).

Requires: Python 3.11+, Pydantic v2.

TEAM CONVENTIONS
- Changes require agreement from all four members.
- Finding.type must exist in TYPE_CATEGORY (the single source of truth).
- start is inclusive; end is exclusive, so text[start:end] is the match.
- confidence must be between 0.0 and 1.0.
- Audit events must never contain raw sensitive content.
- Audit timestamps must be timezone-aware and are normalized to UTC.
- The first audit event uses GENESIS_HASH as prev_hash.
- content_sha256 stores HMAC-SHA256 hex, not a bare SHA-256 hash.
  hmac_key_id says which key produced it, so keys can be rotated.
- HMAC generation, redaction, snippet truncation and hash-chain
  verification belong to the audit service (gateway/audit/security.py),
  not to these models.
- Prompt length limits are enforced by the gateway pipeline (which must
  block AND write an audit event), not by the schema, because a schema
  rejection happens before any detector or audit log runs.

VERSION 1.1.0
- Lines marked "# v1.1" are proposed additions. Remove the marker once agreed.
"""

import re
from datetime import datetime, timezone
from typing import Literal, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator


# ================================================================
# 1. Shared enums and constants
# ================================================================

CONTRACT_VERSION = "1.1.0"  # v1.1

Category = Literal[
    "PII",
    "FINANCIAL",
    "CREDENTIAL",
    "CONFIDENTIAL",
    "INJECTION",
    "RESTRICTED_DOC",
]

Direction = Literal["prompt", "response"]

Action = Literal[
    "allow",
    "warn",
    "mask",
    "redact",
    "block",
    "require_approval",
]

ApprovalStatus = Literal["pending", "approved", "rejected"]

# Enforced by M1's pipeline: oversized prompts are blocked and audited.
MAX_PROMPT_CHARS = 100_000

GENESIS_HASH = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")


# ================================================================
# 2. Canonical finding types (ONE place; KNOWN_TYPES is derived)
# New types require team agreement.
# ================================================================

TYPE_CATEGORY: dict[str, Category] = {
    # M2: personal identifiers
    "AADHAAR": "PII",
    "PAN": "PII",
    "PHONE": "PII",
    "EMAIL": "PII",
    "PERSON": "PII",  # noisy: policy should require a high confidence

    # M2: financial identifiers
    "GSTIN": "FINANCIAL",
    "IFSC": "FINANCIAL",
    "UPI": "FINANCIAL",
    "CARD": "FINANCIAL",

    # M2: credentials and secrets
    "PASSWORD": "CREDENTIAL",
    "API_KEY": "CREDENTIAL",
    "SECRET": "CREDENTIAL",

    # M2: confidential information
    "CONFIDENTIAL_TEXT": "CONFIDENTIAL",
    "SOURCE_CODE": "CONFIDENTIAL",

    # M3: prompt injection
    "SYSTEM_PROMPT_EXTRACTION": "INJECTION",
    "INSTRUCTION_OVERRIDE": "INJECTION",
    "DATA_EXFILTRATION": "INJECTION",
    "INDIRECT_INJECTION": "INJECTION",
    "CANARY_LEAK": "INJECTION",

    # M4: restricted documents
    "RESTRICTED_DOCUMENT": "RESTRICTED_DOC",
}

KNOWN_TYPES: frozenset[str] = frozenset(TYPE_CATEGORY)


# ================================================================
# 3. M2: Detector finding
# ================================================================

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

        # Field validators run before this "after" validator, so an
        # unknown type has already been rejected. .get() keeps this safe
        # even if the type check is ever changed.
        expected = TYPE_CATEGORY.get(self.type)
        if expected is not None and self.category != expected:
            raise ValueError(
                f"Finding type {self.type!r} requires category "
                f"{expected!r}, not {self.category!r}"
            )
        return self


# ================================================================
# 4. User context
# ================================================================

class UserContext(BaseModel):
    user_id: str = Field(min_length=1)
    role: Literal["intern", "hr_officer", "finance_manager", "admin"]
    department: str = Field(min_length=1)
    clearance: int = Field(ge=0, le=3)


# ================================================================
# 5. M3: Prompt-injection result
# ================================================================

class InjectionResult(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    label: Literal["injection", "benign"]
    reasons: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # v1.1: attack types for the policy engine


# ================================================================
# 6. M4: Retrieval-augmented generation
# ================================================================

class Chunk(BaseModel):
    doc_id: str = Field(min_length=1)
    text: str
    score: float | None = None


class RetrievalResult(BaseModel):
    chunks: list[Chunk] = Field(default_factory=list)
    denied_count: int = Field(default=0, ge=0)
    denied_doc_ids: list[str] = Field(default_factory=list)


# ================================================================
# 7. M2: Audit finding summary
# ================================================================

class AuditFinding(BaseModel):
    """Summary only. Never stores the matched text."""

    type: str
    count: int = Field(ge=1)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in KNOWN_TYPES:
            raise ValueError(f"Unknown finding type: {value!r}")
        return value


# ================================================================
# 8. M2: Audit event
# ================================================================

class AuditEvent(BaseModel):
    id: str | None = None

    ts: datetime
    user_id: str = Field(min_length=1)
    direction: Direction

    findings: list[AuditFinding] = Field(default_factory=list)

    policy_id: str | None = None
    action: Action

    # The audit service must scrub and truncate before building the event
    # (see gateway/audit/security.py: make_snippet).
    snippet_redacted: str = Field(max_length=500)

    # Legacy field name kept so M4's mock JSON still matches.
    # Value is HMAC-SHA256 hex of the original content.
    content_sha256: str
    hmac_key_id: str = Field(default="k1", min_length=1, max_length=32)

    # Previous event's hash; GENESIS_HASH for the first event only.
    # The audit service enforces "first event only".
    prev_hash: str

    latency_ms: int = Field(ge=0)

    request_id: str | None = None                             # v1.1: same value as ChatResponse.request_id
    denied_doc_ids: list[str] = Field(default_factory=list)   # v1.1: document IDs only, never content

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


# ================================================================
# 9. M1: Chat API request and response
# ================================================================

class StageReport(BaseModel):                                 # v1.1
    stage: Literal["prompt", "rag", "response"]
    policy_id: str | None = None
    action: Action
    finding_types: list[str] = Field(default_factory=list)


class GatewayReport(BaseModel):                               # v1.1
    stages: list[StageReport] = Field(default_factory=list)
    timings_ms: dict[str, int] = Field(default_factory=dict)  # e.g. inspect_pii, inspect_injection, policy, rag, llm
    denied_doc_ids: list[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
    # No max_length here on purpose: see MAX_PROMPT_CHARS above.
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
    report: GatewayReport | None = None                       # v1.1: None keeps v1.0 clients working


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "rejected"]


class LoginRequest(BaseModel):                                # v1.1
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):                               # v1.1
    access_token: str
    token_type: Literal["bearer"] = "bearer"


# ================================================================
# 10. Shared interfaces
# ================================================================

class Detectors(Protocol):
    """M2 detector interface called by M1."""

    def inspect(
        self, text: str, direction: Direction, ctx: UserContext
    ) -> list[Finding]: ...


class InjectionScorer(Protocol):
    """M3 injection-scoring interface called by M1."""

    def score(
        self, text: str, source: Literal["user", "document"]
    ) -> InjectionResult: ...


class CanaryService(Protocol):                                # v1.1
    """M3 canary interface, called by M1's LLM adapter."""

    def new_token(self, session_id: str) -> str: ...

    def system_prompt_snippet(self, token: str) -> str: ...

    def check_response(self, response_text: str, token: str) -> list[Finding]: ...


class Retriever(Protocol):
    """M4 retrieval interface called by M1."""

    def retrieve(
        self, query: str, user: UserContext, k: int = 4
    ) -> RetrievalResult: ...


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