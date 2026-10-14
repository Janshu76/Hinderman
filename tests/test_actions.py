import pytest

from warden.actions import ActionExecutor
from warden.models import Action, ChatMessage, Finding, Severity
from warden.policies import PolicyDecision


def finding(text: str | None = "person@example.com") -> Finding:
    return Finding(
        category="email",
        severity=Severity.MEDIUM,
        detector="test",
        message="test finding",
        matched_text=text,
        message_index=0 if text else None,
    )


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (Action.MASK, "Contact ***"),
        (Action.REDACT, "Contact [PRIVATE]"),
    ],
)
def test_mask_and_redact_transform_only_matched_values(action, expected):
    decision = PolicyDecision(action, "matched policy", [finding()], "[PRIVATE]")
    result = ActionExecutor().execute(
        decision, [ChatMessage(role="user", content="Contact person@example.com")]
    )
    assert result.messages[0].content == expected
    assert result.affected_items == 1
    assert not result.blocked


def test_allow_and_warn_leave_messages_unchanged():
    message = ChatMessage(role="user", content="Contact person@example.com")
    for action in (Action.ALLOW, Action.WARN):
        result = ActionExecutor().execute(
            PolicyDecision(action, "matched policy", [finding()]), [message]
        )
        assert result.messages == [message]
        assert result.affected_items == 0
        assert not result.blocked


def test_block_stops_request_without_rewriting_input():
    message = ChatMessage(role="user", content="Contact person@example.com")
    result = ActionExecutor().execute(
        PolicyDecision(Action.BLOCK, "blocked", [finding()]), [message]
    )
    assert result.messages == [message]
    assert result.blocked


def test_mask_replaces_every_occurrence_in_one_message():
    match = finding()
    result = ActionExecutor().execute(
        PolicyDecision(Action.MASK, "matched policy", [match]),
        [
            ChatMessage(
                role="user",
                content="person@example.com and person@example.com",
            )
        ],
    )
    assert result.messages[0].content == "*** and ***"
    assert result.affected_items == 2


@pytest.mark.parametrize(
    "invalid_finding",
    [
        finding(text=None),
        Finding(
            category="email",
            severity=Severity.MEDIUM,
            detector="test",
            message="missing index",
            matched_text="person@example.com",
        ),
        Finding(
            category="email",
            severity=Severity.MEDIUM,
            detector="test",
            message="out of range",
            matched_text="person@example.com",
            message_index=1,
        ),
        Finding(
            category="email",
            severity=Severity.MEDIUM,
            detector="test",
            message="not in message",
            matched_text="absent@example.com",
            message_index=0,
        ),
    ],
)
def test_invalid_or_stale_findings_do_not_corrupt_messages(invalid_finding):
    message = ChatMessage(role="user", content="Contact person@example.com")
    result = ActionExecutor().execute(
        PolicyDecision(Action.MASK, "matched policy", [invalid_finding]), [message]
    )
    assert result.messages == [message]
    assert result.affected_items == 0
