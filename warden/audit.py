import json
import logging


class ConsoleAuditLogger:
    """Demo-only audit sink; replace with the production audit module."""

    def __init__(self) -> None:
        self._logger = logging.getLogger("warden.audit")

    def record(self, event: str, **fields: object) -> None:
        self._logger.info(
            "%s",
            json.dumps({"event": event, **fields}, sort_keys=True, default=str),
        )
