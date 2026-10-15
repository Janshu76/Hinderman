"""Human-approval queue for requests the policy marked require_approval."""
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import Index, String, Text, inspect, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from contracts.schemas import ApprovalStatus, Finding, UserContext

from .db import Base, make_engine
from .security import make_snippet, summarize_findings

APPROVER_ROLES = frozenset({"admin"})


class ApprovalError(Exception):
    pass


class ApprovalRow(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    created_ts: Mapped[str] = mapped_column(String(40))
    findings_json: Mapped[str] = mapped_column(Text)
    snippet_redacted: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), index=True)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_ts: Mapped[str | None] = mapped_column(String(40), nullable=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalQueue:
    def __init__(self, url: str | None = None):
        self._engine = make_engine(url)
        Base.metadata.create_all(self._engine)
        request_id_index = next(
            (
                index
                for index in inspect(self._engine).get_indexes("approvals")
                if index["column_names"] == ["request_id"] and index["unique"]
            ),
            None,
        )
        if request_id_index is None:
            Index("uq_approvals_request_id", ApprovalRow.request_id, unique=True).create(
                self._engine, checkfirst=True
            )

    def close(self) -> None:
        self._engine.dispose()

    def enqueue(
        self, request_id: str, findings: list[Finding], redacted_snippet: str
    ) -> str:
        with Session(self._engine) as session:
            existing = session.scalar(
                select(ApprovalRow).where(ApprovalRow.request_id == request_id)
            )
        if existing is not None:
            return existing.approval_id

        approval_id = uuid.uuid4().hex
        summary = [f.model_dump() for f in summarize_findings(findings)]
        try:
            with Session(self._engine) as session, session.begin():
                session.add(
                    ApprovalRow(
                        approval_id=approval_id,
                        request_id=request_id,
                        created_ts=_now(),
                        findings_json=json.dumps(summary, sort_keys=True),
                        snippet_redacted=make_snippet(redacted_snippet),
                        status="pending",
                    )
                )
        except IntegrityError:
            with Session(self._engine) as session:
                existing = session.scalar(
                    select(ApprovalRow).where(ApprovalRow.request_id == request_id)
                )
            if existing is None:
                raise
            return existing.approval_id
        return approval_id

    def get_status(self, approval_id: str) -> ApprovalStatus:
        with Session(self._engine) as session:
            row = session.get(ApprovalRow, approval_id)
        if row is None:
            raise ApprovalError("unknown approval id")
        return row.status

    def list(self, status: ApprovalStatus | None = None, limit: int = 50) -> list[dict]:
        stmt = select(ApprovalRow).order_by(ApprovalRow.created_ts.desc()).limit(
            max(1, min(limit, 500))
        )
        if status:
            stmt = stmt.where(ApprovalRow.status == status)
        with Session(self._engine) as session:
            rows = session.scalars(stmt).all()
        return [
            {
                "approval_id": r.approval_id,
                "request_id": r.request_id,
                "created_ts": r.created_ts,
                "findings": json.loads(r.findings_json),
                "snippet_redacted": r.snippet_redacted,
                "status": r.status,
                "decided_by": r.decided_by,
                "decided_ts": r.decided_ts,
            }
            for r in rows
        ]

    def decide(
        self,
        approval_id: str,
        decision: Literal["approved", "rejected"],
        decider: UserContext,
    ) -> ApprovalStatus:
        if decider.role not in APPROVER_ROLES:
            raise ApprovalError("this role may not decide approvals")
        if decision not in ("approved", "rejected"):
            raise ApprovalError("decision must be 'approved' or 'rejected'")
        with Session(self._engine) as session, session.begin():
            result = session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.approval_id == approval_id, ApprovalRow.status == "pending")
                .values(status=decision, decided_by=decider.user_id, decided_ts=_now())
            )
            if result.rowcount == 0:
                exists = session.get(ApprovalRow, approval_id) is not None
                raise ApprovalError(
                    "approval was already decided" if exists else "unknown approval id"
                )
        return decision


_default: ApprovalQueue | None = None
_default_lock = threading.Lock()


def get_queue() -> ApprovalQueue:
    global _default
    with _default_lock:
        if _default is None:
            _default = ApprovalQueue()
        return _default


def set_queue(queue: ApprovalQueue | None) -> None:
    global _default
    with _default_lock:
        _default = queue


def enqueue_approval(
    request_id: str, findings: list[Finding], redacted_snippet: str
) -> str:
    return get_queue().enqueue(request_id, findings, redacted_snippet)


def get_approval_status(approval_id: str) -> ApprovalStatus:
    return get_queue().get_status(approval_id)
