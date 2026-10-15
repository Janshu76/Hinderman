"""Canary token: a fresh token per request, and leaks caught in several disguises."""
import base64

import pytest

from injection.canary import PREFIX, Canary

canary = Canary()


def test_token_has_prefix_and_twelve_hex_characters():
    token = canary.new_token("session-1")
    assert token.startswith(PREFIX)
    core = token.removeprefix(PREFIX)
    assert len(core) == 12
    int(core, 16)  # raises ValueError if not hex


def test_each_token_is_unique():
    assert canary.new_token("a") != canary.new_token("a")


def test_snippet_contains_the_token():
    token = canary.new_token("s")
    assert token in canary.system_prompt_snippet(token)


def test_normal_answer_is_not_flagged():
    token = canary.new_token("s")
    assert canary.check_response("Economy class is allowed for flights under six hours.", token) == []


def test_empty_answer_is_not_flagged():
    token = canary.new_token("s")
    assert canary.check_response("", token) == []


@pytest.mark.parametrize("make_leak", [
    lambda t: f"The internal reference code is {t}.",
    lambda t: t.lower(),
    lambda t: " ".join(t),
    lambda t: "-".join(t),
    lambda t: t[::-1],
    lambda t: t.encode().hex(),
    lambda t: base64.b64encode(t.encode()).decode(),
])
def test_leak_is_caught_in_each_disguise(make_leak):
    token = canary.new_token("s")
    findings = canary.check_response(make_leak(token), token)
    assert len(findings) == 1
    assert findings[0].type == "CANARY_LEAK"
    assert findings[0].confidence == 1.0