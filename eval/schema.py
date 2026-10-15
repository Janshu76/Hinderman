"""Shape of one test case and one result. Uses the team's contract types."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from contracts import KNOWN_TYPES, Action   # adjust the import to wherever contracts.py lives

Group = Literal["legit", "pii", "injection_direct", "injection_indirect",
                "rag_violation", "benign_lookalike"]
Role = Literal["intern", "hr_officer", "finance_manager", "admin"]

# Groups that should be stopped by the gateway. The rest should pass through.
ATTACK_GROUPS = {"injection_direct", "injection_indirect", "rag_violation"}
# Actions that count as "stopped".
STOP_ACTIONS = {"block", "require_approval"}
# Actions that count as "let through" for a legitimate prompt.
PASS_ACTIONS = {"allow", "warn"}


class EvalCase(BaseModel):
    id: str = Field(min_length=1)
    group: Group
    prompt: str = Field(min_length=1)
    document_text: str | None = None          # poisoned chunk, for indirect cases
    user_role: Role = "intern"
    use_rag: bool = False
    expected_action: Action
    expected_types: list[str] = Field(default_factory=list)
    expected_denied_doc_ids: list[str] = Field(default_factory=list)
    split: Literal["dev", "heldout"] = "dev"
    notes: str = ""

    @field_validator("expected_types")
    @classmethod
    def types_known(cls, value: list[str]) -> list[str]:
        bad = [t for t in value if t not in KNOWN_TYPES]
        if bad:
            raise ValueError(f"Unknown finding types: {bad}")
        return value

    @property
    def is_attack(self) -> bool:
        return self.group in ATTACK_GROUPS


class EvalResult(BaseModel):
    case_id: str
    group: Group
    is_attack: bool
    action_taken: Action
    found_types: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    denied_doc_ids: list[str] = Field(default_factory=list)
    latency_ms: dict[str, int] = Field(default_factory=dict)
    stopped: bool                              # True when the gateway blocked or held the request
    correct: bool                              # attack stopped, or legitimate request let through
    error: str | None = None                   # set if the call itself failed