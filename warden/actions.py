from collections.abc import Sequence

from warden.models import Action, ChatMessage, Finding
from warden.policies import PolicyDecision


class ActionResult:
    def __init__(
        self, messages: list[ChatMessage], blocked: bool, affected_items: int
    ) -> None:
        self.messages = messages
        self.blocked = blocked
        self.affected_items = affected_items


class ActionExecutor:
    def execute(
        self,
        decision: PolicyDecision,
        messages: Sequence[ChatMessage],
    ) -> ActionResult:
        if decision.action == Action.BLOCK:
            return ActionResult(list(messages), blocked=True, affected_items=0)

        replacement = {
            Action.MASK: "***",
            Action.REDACT: decision.replacement,
        }.get(decision.action)
        if replacement is None:
            return ActionResult(list(messages), blocked=False, affected_items=0)

        transformed = list(messages)
        affected_items = 0
        for finding in decision.findings:
            if not finding.matched_text or finding.message_index is None:
                continue
            if not 0 <= finding.message_index < len(transformed):
                continue
            message = transformed[finding.message_index]
            count = message.content.count(finding.matched_text)
            if count:
                transformed[finding.message_index] = message.model_copy(
                    update={
                        "content": message.content.replace(
                            finding.matched_text, replacement
                        )
                    }
                )
                affected_items += count
        return ActionResult(transformed, blocked=False, affected_items=affected_items)
