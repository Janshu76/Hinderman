"""In-process implementation of the shared M2 PlatformServices protocol."""

from contracts.schemas import ApprovalStatus, AuditEvent, Finding, UserContext
from gateway.audit.approvals import ApprovalQueue, get_queue
from gateway.audit.logger import AuditLogger, get_logger
from gateway.auth.jwt_auth import get_current_user, get_user_by_id


class M2PlatformServices:
    """Resolve M2 credentials and delegate audit/approval persistence.

    Use this instance inside the M2 service. A separate M1 process should use
    ``M2PlatformServicesClient`` so every remote operation is service-authenticated.
    """

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        approval_queue: ApprovalQueue | None = None,
    ) -> None:
        self._audit_logger = audit_logger
        self._approval_queue = approval_queue

    def get_current_user(self, token: str) -> UserContext:
        return get_current_user(token)

    def log_event(self, event: AuditEvent) -> str:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be a contracts.schemas.AuditEvent")
        # The M1 service is authenticated separately; the ID still must identify
        # an enabled user in M2's authoritative user store.
        get_user_by_id(event.user_id)
        logger = self._audit_logger or get_logger()
        return logger.log_event(event)

    def enqueue_approval(
        self, request_id: str, findings: list[Finding], redacted_snippet: str
    ) -> str:
        queue = self._approval_queue or get_queue()
        return queue.enqueue(request_id, findings, redacted_snippet)

    def get_approval_status(self, approval_id: str) -> ApprovalStatus:
        queue = self._approval_queue or get_queue()
        return queue.get_status(approval_id)
