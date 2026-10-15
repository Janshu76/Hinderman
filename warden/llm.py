import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import httpx

from warden.models import PromptMessage

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LLMSettings:
    ollama_model: str
    ollama_api_base: str
    hosted_model: str
    hosted_api_key: str | None
    timeout_seconds: float = 180


@dataclass(frozen=True)
class CompletionResult:
    text: str
    model: str
    fallback_used: bool


class LLMUnavailableError(RuntimeError):
    """All configured LLM providers failed to return a completion."""


class LLMAdapter(Protocol):
    async def complete(
        self, messages: Sequence[PromptMessage]
    ) -> CompletionResult: ...


class OllamaHTTPAdapter:
    def __init__(self, settings: LLMSettings) -> None:
        self.settings = settings

    async def complete(
        self, messages: Sequence[PromptMessage]
    ) -> CompletionResult:
        model = self.settings.ollama_model.removeprefix("ollama_chat/")
        url = f"{self.settings.ollama_api_base.rstrip('/')}/api/chat"
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.timeout_seconds
            ) as client:
                response = await client.post(
                    url,
                    json={
                        "model": model,
                        "messages": [message.model_dump() for message in messages],
                        "stream": False,
                        "think": False,
                        "options": {"num_predict": 256},
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("Local Ollama request failed: %r", exc)
            raise LLMUnavailableError(
                "The local Ollama request failed."
            ) from exc

        message = payload.get("message") if isinstance(payload, dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise LLMUnavailableError(
                "The local Ollama response did not contain text."
            )
        return CompletionResult(
            text=text,
            model=self.settings.ollama_model,
            fallback_used=False,
        )


class LiteLLMAdapter:
    def __init__(self, settings: LLMSettings) -> None:
        self.settings = settings

    async def complete(
        self, messages: Sequence[PromptMessage]
    ) -> CompletionResult:
        try:
            return await self._complete(
                self.settings.ollama_model, self.settings.ollama_api_base, messages
            )
        except Exception as local_error:
            if not self.settings.hosted_api_key:
                logger.error(
                    "Local LLM request failed and no hosted fallback is configured: %s",
                    local_error,
                )
                raise LLMUnavailableError(
                    "The local LLM request failed and no hosted fallback is configured."
                ) from local_error
            logger.warning("Local LLM request failed; trying hosted fallback: %s", local_error)
            try:
                return await self._complete(
                    self.settings.hosted_model,
                    None,
                    messages,
                    api_key=self.settings.hosted_api_key,
                )
            except Exception as fallback_error:
                logger.exception("Both local and hosted LLM requests failed")
                raise LLMUnavailableError(
                    "Both the local LLM and hosted fallback requests failed."
                ) from fallback_error

    async def _complete(
        self,
        model: str,
        api_base: str | None,
        messages: Sequence[PromptMessage],
        api_key: str | None = None,
    ) -> CompletionResult:
        from litellm import acompletion

        response = await acompletion(
            model=model,
            messages=[message.model_dump() for message in messages],
            api_base=api_base,
            api_key=api_key,
            timeout=self.settings.timeout_seconds,
        )
        text = response.choices[0].message.content
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("The configured LLM returned an empty or non-text response.")
        return CompletionResult(text=text, model=model, fallback_used=api_base is None)
