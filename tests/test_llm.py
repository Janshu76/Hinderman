from collections.abc import Sequence
from types import SimpleNamespace

import pytest

import litellm
from warden.llm import (
    CompletionResult,
    LLMSettings,
    LLMUnavailableError,
    LiteLLMAdapter,
)
from warden.models import PromptMessage


@pytest.mark.asyncio
async def test_local_failure_uses_configured_hosted_fallback(monkeypatch):
    adapter = LiteLLMAdapter(
        LLMSettings(
            ollama_model="ollama_chat/demo",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key="configured-key",
        )
    )
    calls = []

    async def complete(model, api_base, messages, api_key=None):
        calls.append((model, api_base, api_key))
        if api_base is not None:
            raise ConnectionError("local server offline")
        return CompletionResult("hosted reply", model, True)

    monkeypatch.setattr(adapter, "_complete", complete)
    result = await adapter.complete(
        [PromptMessage(role="user", content="hello")]
    )
    assert result.text == "hosted reply"
    assert result.fallback_used
    assert calls == [
        ("ollama_chat/demo", "http://ollama:11434", None),
        ("openai/demo", None, "configured-key"),
    ]


@pytest.mark.asyncio
async def test_local_failure_without_hosted_key_is_explicit(monkeypatch):
    adapter = LiteLLMAdapter(
        LLMSettings(
            ollama_model="ollama_chat/demo",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key=None,
        )
    )

    async def fail(model, api_base, messages, api_key=None):
        raise ConnectionError("local server offline")

    monkeypatch.setattr(adapter, "_complete", fail)
    with pytest.raises(LLMUnavailableError, match="no hosted fallback"):
        await adapter.complete([PromptMessage(role="user", content="hello")])


@pytest.mark.asyncio
async def test_litellm_call_receives_gateway_system_prompt(monkeypatch):
    adapter = LiteLLMAdapter(
        LLMSettings(
            ollama_model="ollama_chat/demo",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key=None,
        )
    )
    captured = {}

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content="local response"))
            ]
        )

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    result = await adapter.complete(
        [
            PromptMessage(role="system", content="gateway system prompt"),
            PromptMessage(role="user", content="hello"),
        ]
    )
    assert result == CompletionResult("local response", "ollama_chat/demo", False)
    assert captured["model"] == "ollama_chat/demo"
    assert captured["api_base"] == "http://ollama:11434"
    assert captured["messages"][0]["role"] == "system"


@pytest.mark.asyncio
async def test_both_llm_providers_failing_returns_explicit_error(monkeypatch):
    adapter = LiteLLMAdapter(
        LLMSettings(
            ollama_model="ollama_chat/demo",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key="configured-key",
        )
    )
    calls = []

    async def fail(model, api_base, messages, api_key=None):
        calls.append(model)
        raise ConnectionError("provider unavailable")

    monkeypatch.setattr(adapter, "_complete", fail)
    with pytest.raises(
        LLMUnavailableError, match="Both the local LLM and hosted fallback"
    ):
        await adapter.complete([PromptMessage(role="user", content="hello")])
    assert calls == ["ollama_chat/demo", "openai/demo"]


@pytest.mark.asyncio
@pytest.mark.parametrize("response_content", [None, "", "  "])
async def test_empty_llm_response_is_rejected_and_can_fallback(
    monkeypatch, response_content
):
    adapter = LiteLLMAdapter(
        LLMSettings(
            ollama_model="ollama_chat/demo",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key="configured-key",
        )
    )
    calls = []

    async def fake_acompletion(**kwargs):
        calls.append(kwargs["model"])
        content = response_content if len(calls) == 1 else "hosted response"
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    result = await adapter.complete([PromptMessage(role="user", content="hello")])
    assert result.text == "hosted response"
    assert result.fallback_used
    assert calls == ["ollama_chat/demo", "openai/demo"]
