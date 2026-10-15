"""Tamper-evident audit log.

Every row stores the previous row's hash. Each row hash is an HMAC over the
row's contents plus that previous hash, so editing or removing a row breaks
the chain from that point on.

The logger assigns prev_hash itself inside a locked transaction. The
prev_hash on the AuditEvent passed to log_event is ignored, because the
caller cannot know the latest hash.
"""
import hashlib
import hmac
import json
import threading
import uuid
from dataclasses import dataclass

from sqlalchemy import Index, Integer, String, Text, inspect, select, text
from sqlalchemy.orm import Mapped, Session, mapped_column

from contracts.schemas import GENESIS_HASH, AuditEvent

from .db import Base, make_engine
from .security import MIN_KEY_CHARS, load_hmac_key, make_snippet


class AuditRow(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(64), unique=True)
    ts: Mapped[str] = mapped_column(String(40))
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    direction: Mapped[str] = mapped_column(String(16))
    findings_json: Mapped[str] = mapped_column(Text)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    snippet_redacted: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    hmac_key_id: Mapped[str] = mapped_column(String(32))
    latency_ms: Mapped[int] = mapped_column(Integer)
    denied_doc_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    chain_key_id: Mapped[str] = mapped_column(String(32))
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    row_hash: Mapped[str] = mapped_column(String(64))


@dataclass(frozen=True)
class ChainResult:
    ok: bool
    checked: int
    bad_seq: int | None = None
    reason: str | None = None


def _canonical(fields: dict) -> bytes:
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _row_fields(row: AuditRow) -> dict:
    fields = {
        "id": row.id,
        "ts": row.ts,
        "user_id": row.user_id,
        "direction": row.direction,
        "findings_json": row.findings_json,
        "policy_id": row.policy_id,
        "action": row.action,
        "snippet_redacted": row.snippet_redacted,
        "content_sha256": row.content_sha256,
        "hmac_key_id": row.hmac_key_id,
        "latency_ms": row.latency_ms,
        "chain_key_id": row.chain_key_id,
        "prev_hash": row.prev_hash,
    }
    # Preserve verification of rows written before the integration columns existed.
    if row.request_id is not None or row.denied_doc_ids_json != "[]":
        fields["request_id"] = row.request_id
        fields["denied_doc_ids_json"] = row.denied_doc_ids_json
    return fields


def _row_hash(key: bytes, fields: dict) -> str:
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


class AuditLogger:
    def __init__(self, key: bytes, key_id: str = "k1", url: str | None = None):
        if len(key) < MIN_KEY_CHARS:
            raise ValueError(f"key must be at least {MIN_KEY_CHARS} bytes")
        self._key = key
        self._key_id = key_id
        self._engine = make_engine(url)
        Base.metadata.create_all(self._engine)
        columns = {column["name"] for column in inspect(self._engine).get_columns("audit_events")}
        with self._engine.begin() as connection:
            if "request_id" not in columns:
                connection.execute(text("ALTER TABLE audit_events ADD COLUMN request_id VARCHAR(64)"))
            if "denied_doc_ids_json" not in columns:
                connection.execute(
                    text("ALTER TABLE audit_events ADD COLUMN "
                         "denied_doc_ids_json TEXT NOT NULL DEFAULT '[]'")
                )
        if "request_id" not in columns:
            Index("ix_audit_events_request_id", AuditRow.request_id).create(
                self._engine, checkfirst=True
            )
        self._lock = threading.Lock()

    def close(self) -> None:
        self._engine.dispose()

    def log_event(self, event: AuditEvent) -> str:
        event_id = event.id or uuid.uuid4().hex
        findings_json = json.dumps(
            [f.model_dump() for f in event.findings],
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock, Session(self._engine) as session, session.begin():
            last = session.scalar(select(AuditRow).order_by(AuditRow.seq.desc()).limit(1))
            row = AuditRow(
                id=event_id,
                ts=event.ts.isoformat(),
                request_id=event.request_id or event.id or event_id,
                user_id=event.user_id,
                direction=event.direction,
                findings_json=findings_json,
                policy_id=event.policy_id,
                action=event.action,
                snippet_redacted=make_snippet(event.snippet_redacted),
                content_sha256=event.content_sha256,
                hmac_key_id=event.hmac_key_id,
                latency_ms=event.latency_ms,
                denied_doc_ids_json=json.dumps(event.denied_doc_ids, separators=(",", ":")),
                chain_key_id=self._key_id,
                prev_hash=last.row_hash if last else GENESIS_HASH,
                row_hash="",
            )
            row.row_hash = _row_hash(self._key, _row_fields(row))
            session.add(row)
        return event_id

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        user_id: str | None = None,
        action: str | None = None,
    ) -> list[dict]:
        limit = max(1, min(limit, 500))
        stmt = select(AuditRow).order_by(AuditRow.seq.desc()).limit(limit).offset(offset)
        if user_id:
            stmt = stmt.where(AuditRow.user_id == user_id)
        if action:
            stmt = stmt.where(AuditRow.action == action)
        with Session(self._engine) as session:
            rows = session.scalars(stmt).all()
        return [
            {
                "id": r.id,
                "ts": r.ts,
                "request_id": r.request_id,
                "user_id": r.user_id,
                "direction": r.direction,
                "findings": json.loads(r.findings_json),
                "policy_id": r.policy_id,
                "action": r.action,
                "snippet_redacted": r.snippet_redacted,
                "latency_ms": r.latency_ms,
                "denied_doc_ids": json.loads(r.denied_doc_ids_json),
            }
            for r in rows
        ]

    def verify_chain(self, keys: dict[str, bytes] | None = None) -> ChainResult:
        """Check every row in order. `keys` maps chain_key_id to key (for rotated keys)."""
        keys = keys or {self._key_id: self._key}
        expected_prev = GENESIS_HASH
        checked = 0
        with Session(self._engine) as session:
            for row in session.scalars(select(AuditRow).order_by(AuditRow.seq)):
                checked += 1
                if row.prev_hash != expected_prev:
                    return ChainResult(
                        False, checked, row.seq,
                        "prev_hash does not match the previous row (row removed or reordered)",
                    )
                key = keys.get(row.chain_key_id)
                if key is None:
                    return ChainResult(
                        False, checked, row.seq, f"no key for {row.chain_key_id!r}"
                    )
                if not hmac.compare_digest(_row_hash(key, _row_fields(row)), row.row_hash):
                    return ChainResult(False, checked, row.seq, "row contents were modified")
                expected_prev = row.row_hash
        return ChainResult(True, checked)


_default: AuditLogger | None = None
_default_lock = threading.Lock()


def get_logger() -> AuditLogger:
    global _default
    with _default_lock:
        if _default is None:
            key, key_id = load_hmac_key()
            _default = AuditLogger(key, key_id)
        return _default


def set_logger(logger: AuditLogger | None) -> None:
    global _default
    with _default_lock:
        _default = logger


def log_event(event: AuditEvent) -> str:
    return get_logger().log_event(event)


def verify_chain() -> ChainResult:
    return get_logger().verify_chain()
