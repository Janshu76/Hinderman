from typing import Literal

from pydantic import BaseModel, Field


class UserContext(BaseModel):
    user_id: str = Field(min_length=1)
    role: Literal["intern", "hr_officer", "finance_manager", "admin"]
    department: str = Field(min_length=1)
    clearance: int = Field(ge=0, le=3)


class Chunk(BaseModel):
    doc_id: str = Field(min_length=1)
    text: str
    score: float | None = None


class RetrievalResult(BaseModel):
    chunks: list[Chunk] = Field(default_factory=list)
    denied_count: int = Field(default=0, ge=0)
    denied_doc_ids: list[str] = Field(default_factory=list)
