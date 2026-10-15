from datetime import datetime, timezone

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from contracts.schemas import AuditEvent, AuditFinding, GENESIS_HASH
from gateway.audit.logger import AuditLogger, AuditRow

KEY = b"audit-test-key-that-is-at-least-32-bytes-long"


def make_event(**overrides):
    data = dict(
        ts=datetime.now(timezone.utc), user_id="u1", direction="prompt",
        findings=[AuditFinding(type="PAN", count=1, confidence=0.9)],
        action="mask", snippet_redacted="PAN ABCPE1234F", content_sha256="a" * 64,
        hmac_key_id="k1", prev_hash=GENESIS_HASH, latency_ms=12,
    )
    data.update(overrides)
    return AuditEvent(**data)


@pytest.fixture
def logger(tmp_path):
    db_path = tmp_path / "audit-test.sqlite"
    instance = AuditLogger(KEY, key_id="chain-k1", url=f"sqlite:///{db_path.as_posix()}")
    yield instance
    instance.close()


def test_logger_rejects_too_short_chain_key(tmp_path):
    with pytest.raises(ValueError, match="at least"):
        AuditLogger(b"short", url=f"sqlite:///{(tmp_path / 'bad.sqlite').as_posix()}")


def test_log_event_returns_id_and_redacts_snippet(logger):
    event_id = logger.log_event(make_event(snippet_redacted="Contact 9876543210, PAN ABCPE1234F"))
    assert isinstance(event_id, str) and event_id
    rows = logger.list_events()
    assert len(rows) == 1
    assert rows[0]["id"] == event_id
    assert "9876543210" not in rows[0]["snippet_redacted"]
    assert "ABCPE1234F" not in rows[0]["snippet_redacted"]


def test_first_event_uses_genesis_and_chain_verifies(logger):
    logger.log_event(make_event())
    with Session(logger._engine) as session:
        row = session.scalar(select(AuditRow))
        assert row.prev_hash == GENESIS_HASH
    result = logger.verify_chain()
    assert result.ok and result.checked == 1


def test_multiple_events_form_valid_chain(logger):
    logger.log_event(make_event(id="event-one"))
    logger.log_event(make_event(id="event-two", action="warn"))
    result = logger.verify_chain()
    assert result.ok and result.checked == 2


def test_list_events_filters_and_orders_newest_first(logger):
    logger.log_event(make_event(id="event-one", user_id="u1", action="mask"))
    logger.log_event(make_event(id="event-two", user_id="u2", action="block"))
    assert [r["id"] for r in logger.list_events(user_id="u1")] == ["event-one"]
    assert [r["id"] for r in logger.list_events(action="block")] == ["event-two"]
    assert len(logger.list_events(limit=1)) == 1


def test_tampering_with_persisted_row_breaks_chain(logger):
    logger.log_event(make_event(id="event-one"))
    with Session(logger._engine) as session, session.begin():
        session.execute(update(AuditRow).where(AuditRow.id == "event-one").values(snippet_redacted="tampered"))
    result = logger.verify_chain()
    assert not result.ok
    assert result.checked == 1
    assert result.reason == "row contents were modified"


def test_verify_chain_detects_unknown_chain_key_id(logger):
    logger.log_event(make_event())
    result = logger.verify_chain(keys={"other-key": KEY})
    assert not result.ok and result.checked == 1
    assert "no key" in result.reason
