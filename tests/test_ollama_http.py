import asyncio

import httpx

from warden.llm import CompletionResult, LLMSettings, LLMUnavailableError, OllamaHTTPAdapter
from warden.models import PromptMessage


def test_ollama_http_adapter_sends_messages_and_returns_reply(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "local response"}}

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def post(self, url, json):
            captured["url"] = url
            captured["body"] = json
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    adapter = OllamaHTTPAdapter(
        LLMSettings(
            ollama_model="ollama_chat/qwen3.5:4b",
            ollama_api_base="http://ollama:11434/",
            hosted_model="openai/demo",
            hosted_api_key=None,
        )
    )

    result = asyncio.run(
        adapter.complete(
            [
                PromptMessage(role="system", content="gateway instructions"),
                PromptMessage(role="user", content="hello"),
            ]
        )
    )

    assert result == CompletionResult("local response", "ollama_chat/qwen3.5:4b", False)
    assert captured["url"] == "http://ollama:11434/api/chat"
    assert captured["body"]["model"] == "qwen3.5:4b"
    assert captured["body"]["stream"] is False
    assert captured["body"]["think"] is False
    assert captured["body"]["options"]["num_predict"] == 256
    assert captured["body"]["messages"][0]["role"] == "system"


def test_ollama_http_adapter_rejects_empty_reply(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": " "}}

    class FakeClient:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    adapter = OllamaHTTPAdapter(
        LLMSettings(
            ollama_model="ollama_chat/qwen3.5:4b",
            ollama_api_base="http://ollama:11434",
            hosted_model="openai/demo",
            hosted_api_key=None,
        )
    )

    try:
        asyncio.run(adapter.complete([PromptMessage(role="user", content="hello")]))
    except LLMUnavailableError as exc:
        assert "did not contain text" in str(exc)
    else:
        raise AssertionError("expected the empty Ollama reply to be rejected")
