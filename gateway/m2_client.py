"""Synchronous HTTP client implementing M1's PlatformServices protocol."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from contracts.schemas import (
    ApprovalEnqueueRequest,
    ApprovalStatus,
    AuditEvent,
    AuditEventResponse,
    Finding,
    TokenResolutionRequest,
    UserContext,
)


class M2ServiceError(RuntimeError):
    """A failed or malformed response from the authenticated M2 service."""


MIN_SERVICE_TOKEN_CHARS = 32


class M2PlatformServicesClient:
    def __init__(self, base_url: str, service_token: str, timeout: float = 5.0) -> None:
        parsed_url = urlsplit(base_url)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            raise ValueError("base_url must be an absolute http:// or https:// URL")
        if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ValueError("base_url must not contain credentials, a query, or a fragment")
        if parsed_url.scheme == "http" and parsed_url.hostname not in {
            "localhost", "127.0.0.1", "::1"
        }:
            raise ValueError("non-local M2 service URLs must use HTTPS")
        if len(service_token) < MIN_SERVICE_TOKEN_CHARS:
            raise ValueError(
                f"service_token must be at least {MIN_SERVICE_TOKEN_CHARS} characters"
            )
        self._base_url = base_url.rstrip("/")
        self._service_token = service_token
        self._timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = Request(
            self._base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._service_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                payload = response.read()
        except HTTPError as exc:
            raise M2ServiceError(f"M2 request failed with HTTP {exc.code}") from exc
        except URLError as exc:
            raise M2ServiceError(f"M2 service is unavailable: {exc.reason}") from exc
        try:
            result = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise M2ServiceError("M2 returned an invalid JSON response") from exc
        if not isinstance(result, dict):
            raise M2ServiceError("M2 returned an invalid response shape")
        return result

    def get_current_user(self, token: str) -> UserContext:
        request = TokenResolutionRequest(access_token=token)
        result = self._request(
            "POST", "/internal/auth/resolve", request.model_dump(mode="json")
        )
        try:
            return UserContext.model_validate(result)
        except ValueError as exc:
            raise M2ServiceError("M2 returned an invalid user context") from exc

    def log_event(self, event: AuditEvent) -> str:
        result = self._request(
            "POST", "/internal/audit/events", event.model_dump(mode="json")
        )
        try:
            return AuditEventResponse.model_validate(result).event_id
        except ValueError as exc:
            raise M2ServiceError("M2 returned an invalid audit response") from exc

    def enqueue_approval(
        self, request_id: str, findings: list[Finding], redacted_snippet: str
    ) -> str:
        payload = ApprovalEnqueueRequest(
            request_id=request_id,
            findings=findings,
            redacted_snippet=redacted_snippet,
        )
        result = self._request(
            "POST", "/internal/approvals", payload.model_dump(mode="json")
        )
        approval_id = result.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise M2ServiceError("M2 returned an invalid approval response")
        return approval_id

    def get_approval_status(self, approval_id: str) -> ApprovalStatus:
        result = self._request("GET", f"/internal/approvals/{quote(approval_id, safe='')}")
        status = result.get("status")
        if status not in ("pending", "approved", "rejected"):
            raise M2ServiceError("M2 returned an invalid approval status")
        return status
