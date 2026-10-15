"""HTTP boundary for M1/M4 to call M2's trusted platform services."""

import hmac
import os
from functools import lru_cache

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy.exc import SQLAlchemyError

from contracts.schemas import (
    ApprovalEnqueueRequest,
    ApprovalEnqueueResponse,
    AuditEvent,
    AuditEventResponse,
    LoginRequest,
    TokenResolutionRequest,
    TokenResponse,
    UserContext,
)
from gateway.auth.jwt_auth import AuthError, login
from gateway.audit.approvals import ApprovalError
from gateway.platform_services import M2PlatformServices

MIN_SERVICE_TOKEN_CHARS = 32


@lru_cache(maxsize=1)
def _default_services() -> M2PlatformServices:
    return M2PlatformServices()


def create_app(
    services: M2PlatformServices | None = None,
    internal_service_token: str | None = None,
) -> FastAPI:
    app = FastAPI(title="Hinderman M2 Platform Services", version="1.0")
    platform = services or _default_services()

    def require_internal_service(
        authorization: str | None = Header(default=None),
    ) -> None:
        expected = internal_service_token or os.environ.get("M2_SERVICE_TOKEN", "")
        if len(expected) < MIN_SERVICE_TOKEN_CHARS:
            raise HTTPException(status_code=503, detail="M2 service authentication is not configured")
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="service authentication required")
        supplied = authorization[7:].strip()
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="invalid service credentials")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/login", response_model=TokenResponse)
    def issue_token(request: LoginRequest) -> TokenResponse:
        try:
            return TokenResponse(access_token=login(request.username, request.password))
        except AuthError as exc:
            raise HTTPException(status_code=401, detail="invalid username or password") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="authentication is not configured") from exc

    @app.post(
        "/internal/auth/resolve",
        response_model=UserContext,
        dependencies=[Depends(require_internal_service)],
    )
    def resolve_token(request: TokenResolutionRequest) -> UserContext:
        try:
            return platform.get_current_user(request.access_token)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail="invalid, expired, disabled, or unknown user token") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="authentication is not configured") from exc

    @app.post(
        "/internal/audit/events",
        response_model=AuditEventResponse,
        dependencies=[Depends(require_internal_service)],
    )
    def persist_audit_event(event: AuditEvent) -> AuditEventResponse:
        try:
            event_id = platform.log_event(event)
        except AuthError as exc:
            raise HTTPException(status_code=422, detail="audit event user is not enabled") from exc
        except (SQLAlchemyError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="audit persistence failed") from exc
        return AuditEventResponse(event_id=event_id)

    @app.post(
        "/internal/approvals",
        response_model=ApprovalEnqueueResponse,
        dependencies=[Depends(require_internal_service)],
    )
    def enqueue_approval(request: ApprovalEnqueueRequest) -> ApprovalEnqueueResponse:
        try:
            approval_id = platform.enqueue_approval(
                request.request_id, request.findings, request.redacted_snippet
            )
        except (SQLAlchemyError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="approval persistence failed") from exc
        return ApprovalEnqueueResponse(approval_id=approval_id)

    @app.get(
        "/internal/approvals/{approval_id}",
        dependencies=[Depends(require_internal_service)],
    )
    def get_approval_status(approval_id: str) -> dict[str, str]:
        try:
            status = platform.get_approval_status(approval_id)
        except (ApprovalError, KeyError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="unknown approval id") from exc
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=503, detail="approval storage failed") from exc
        return {"approval_id": approval_id, "status": status}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway.service:app", host="127.0.0.1", port=8000)
