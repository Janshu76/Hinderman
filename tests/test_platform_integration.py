from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from contracts.schemas import (
    AuditEvent,
    AuditFinding,
    Finding,
    GENESIS_HASH,
    PlatformServices,
    UserContext,
)
from gateway.audit.approvals import ApprovalQueue
from gateway.audit.logger import AuditLogger, AuditRow
from gateway.audit.security import compute_content_hmac
from gateway.auth import jwt_auth
from gateway.m2_client import M2PlatformServicesClient
from gateway.platform_services import M2PlatformServices
from gateway.service import create_app

_JWT_SECRET = "integration-test-jwt-secret-at-least-32-chars"
_SERVICE_TOKEN = "integration-test-service-secret-123"
_AUDIT_KEY = b"integration-test-audit-key-that-is-long-enough"


@pytest.fixture
def platform(tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", _JWT_SECRET)
    monkeypatch.setenv("DEMO_USER_PASSWORD", "integration-demo-password")
    jwt_auth._user_store.cache_clear()
    audit = AuditLogger(
        _AUDIT_KEY,
        key_id="test-chain",
        url=f"sqlite:///{(tmp_path / 'integration.sqlite').as_posix()}",
    )
    approvals = ApprovalQueue(url=f"sqlite:///{(tmp_path / 'integration.sqlite').as_posix()}")
    instance = M2PlatformServices(audit_logger=audit, approval_queue=approvals)
    yield instance
    audit.close()
    approvals.close()
    jwt_auth._user_store.cache_clear()


def _event(**overrides):
    values = {
        "request_id": "request-123",
        "ts": datetime.now(timezone.utc),
        "user_id": "u1",
        "direction": "prompt",
        "findings": [AuditFinding(type="EMAIL", count=1, confidence=0.9)],
        "action": "mask",
        "snippet_redacted": "Contact [EMAIL] for details.",
        "content_sha256": compute_content_hmac("raw prompt", _AUDIT_KEY),
        "hmac_key_id": "test-content",
        "prev_hash": GENESIS_HASH,
        "latency_ms": 23,
        "denied_doc_ids": ["restricted-doc-7"],
    }
    values.update(overrides)
    return AuditEvent(**values)


def _service_headers():
    return {"Authorization": f"Bearer {_SERVICE_TOKEN}"}


def test_adapter_and_remote_client_conform_to_platform_protocol(platform):
    assert isinstance(platform, PlatformServices)
    assert isinstance(
        M2PlatformServicesClient("http://127.0.0.1:8000", _SERVICE_TOKEN),
        PlatformServices,
    )


def test_resolver_returns_authoritative_context_and_ignores_role_claims(platform):
    token = jwt_auth.login("intern", "integration-demo-password")
    claims = jwt.decode(
        token,
        _JWT_SECRET,
        algorithms=[jwt_auth.ALGORITHM],
        audience=jwt_auth.TOKEN_AUDIENCE,
        issuer=jwt_auth.TOKEN_ISSUER,
    )
    assert set(claims) == {"sub", "iat", "exp", "iss", "aud"}
    assert claims["iss"] == "hinderman-m2"
    assert claims["aud"] == "hinderman-m1-m4"
    claims["role"] = "admin"
    claims["department"] = "finance"
    claims["clearance"] = 3
    forged_claims_token = jwt.encode(claims, _JWT_SECRET, algorithm=jwt_auth.ALGORITHM)

    resolved = platform.get_current_user(forged_claims_token)
    assert resolved == UserContext(
        user_id="u1", role="intern", department="general", clearance=0
    )


@pytest.mark.parametrize("token_kind", ["invalid", "expired", "tampered", "unknown"])
def test_resolver_rejects_invalid_expired_tampered_and_unknown_tokens(platform, token_kind):
    if token_kind == "invalid":
        token = "not.a.jwt"
    elif token_kind == "expired":
        user = jwt_auth.authenticate("intern", "integration-demo-password")
        token = jwt_auth.create_access_token(user, ttl_minutes=-1)
    elif token_kind == "tampered":
        valid = jwt_auth.login("intern", "integration-demo-password")
        head, body, signature = valid.split(".")
        token = f"{head}.{body}.{('A' if signature[0] != 'A' else 'B')}{signature[1:]}"
    else:
        token = jwt.encode(
            {
                "sub": "unknown-user",
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
                "iss": jwt_auth.TOKEN_ISSUER,
                "aud": jwt_auth.TOKEN_AUDIENCE,
            },
            _JWT_SECRET,
            algorithm=jwt_auth.ALGORITHM,
        )
    with pytest.raises(jwt_auth.AuthError):
        platform.get_current_user(token)


def test_resolver_rejects_disabled_user(platform):
    token = jwt_auth.login("intern", "integration-demo-password")
    jwt_auth.set_user_enabled("u1", False)
    try:
        assert jwt_auth.authenticate("intern", "integration-demo-password") is None
        with pytest.raises(jwt_auth.AuthError):
            platform.get_current_user(token)
    finally:
        jwt_auth.set_user_enabled("u1", True)


def test_audit_persists_request_metadata_and_scrubs_secrets(platform):
    email = "private.person@example.com"
    phone = "9876543210"
    event = _event(
        snippet_redacted=f"Contact {email}, phone {phone}, bearer eyJabcdefgh.eyJabcdefgh.signature"
    )
    event_id = platform.log_event(event)

    with Session(platform._audit_logger._engine) as session:
        row = session.query(AuditRow).one()
        persisted = repr(row.__dict__)
    assert event_id == row.id
    assert row.request_id == "request-123"
    assert row.user_id == "u1"
    assert row.action == "mask"
    assert row.denied_doc_ids_json == '["restricted-doc-7"]'
    assert email not in persisted
    assert phone not in persisted
    assert "eyJabcdefgh" not in persisted
    assert "raw prompt" not in persisted
    assert platform._audit_logger.verify_chain().ok


def test_approval_enqueue_is_retry_safe(platform):
    finding = Finding(
        category="PII", type="EMAIL", start=0, end=10,
        confidence=0.9, detector="test",
    )
    first = platform.enqueue_approval("request-retry", [finding], "safe [EMAIL]")
    second = platform.enqueue_approval("request-retry", [finding], "safe [EMAIL]")
    rows = platform._approval_queue.list()
    assert first == second
    assert len([row for row in rows if row["request_id"] == "request-retry"]) == 1


def test_internal_api_protects_resolution_and_ignores_browser_identity(platform):
    client = TestClient(create_app(platform, internal_service_token=_SERVICE_TOKEN))
    token_response = client.post(
        "/auth/login",
        json={"username": "intern", "password": "integration-demo-password"},
    )
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]

    assert client.post("/internal/auth/resolve", json={"access_token": token}).status_code == 401
    resolved = client.post(
        "/internal/auth/resolve",
        headers=_service_headers(),
        json={
            "access_token": token,
            "role": "admin",
            "department": "finance",
            "clearance": 3,
        },
    )
    assert resolved.status_code == 422
    resolved = client.post(
        "/internal/auth/resolve",
        headers=_service_headers(),
        json={"access_token": token},
    )
    assert resolved.status_code == 200
    assert resolved.json() == {
        "user_id": "u1", "role": "intern", "department": "general", "clearance": 0
    }


def test_internal_api_persists_audit_and_idempotent_approval(platform):
    client = TestClient(create_app(platform, internal_service_token=_SERVICE_TOKEN))
    event = _event()
    logged = client.post(
        "/internal/audit/events",
        headers=_service_headers(),
        json=event.model_dump(mode="json"),
    )
    assert logged.status_code == 200
    assert logged.json()["event_id"]

    finding = Finding(
        category="PII", type="EMAIL", start=0, end=10,
        confidence=0.9, detector="test",
    )
    body = {
        "request_id": "api-approval-request",
        "findings": [finding.model_dump(mode="json")],
        "redacted_snippet": "safe [EMAIL]",
    }
    first = client.post("/internal/approvals", headers=_service_headers(), json=body)
    second = client.post("/internal/approvals", headers=_service_headers(), json=body)
    assert first.status_code == second.status_code == 200
    assert first.json()["approval_id"] == second.json()["approval_id"]
