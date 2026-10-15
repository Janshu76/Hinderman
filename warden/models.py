from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    MASK = "mask"
    REDACT = "redact"
    BLOCK = "block"


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=32_000)


class PromptMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=32_000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(default="demo", min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)


class RetrievedChunk(BaseModel):
    doc_id: str = Field(min_length=1)
    text: str
    score: float | None = None


class RetrievedSource(BaseModel):
    doc_id: str = Field(min_length=1)
    score: float | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    severity: Severity
    detector: str
    message: str
    matched_text: str | None = None
    message_index: int | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    min_severity: Severity = Severity.LOW
    action: Action
    replacement: str = "[REDACTED]"
    priority: int = 0
    enabled: bool = True


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)
    rules: list[PolicyRule] = Field(min_length=1)


class PublicFinding(BaseModel):
    category: str
    severity: Severity
    detector: str
    message: str


class GatewayReport(BaseModel):
    action: Action
    reason: str
    detectors_run: list[str]
    findings: list[PublicFinding]
    affected_items: int = 0
    blocked: bool = False
    model: str | None = None
    fallback_used: bool = False
    duration_ms: int


class ChatResponse(BaseModel):
    reply: str
    gateway_report: GatewayReport
    sources: list[RetrievedSource] = Field(default_factory=list)
