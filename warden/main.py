import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

from warden.detectors import (
    Detector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    StubAuthDetector,
)
from warden.gateway import Gateway
from warden.llm import LLMAdapter, LLMSettings, LLMUnavailableError, LiteLLMAdapter
from warden.models import ChatRequest, ChatResponse, PolicyDocument
from warden.policies import PolicyFileError, PolicyStore


@dataclass(frozen=True)
class Settings:
    policies_path: Path
    ollama_model: str
    ollama_api_base: str
    hosted_model: str
    hosted_api_key: str | None
    canary_token: str
    admin_api_key: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            policies_path=Path(
                os.getenv("WARDEN_POLICIES_PATH", "config/policies.yaml")
            ),
            ollama_model=os.getenv("WARDEN_OLLAMA_MODEL", "ollama_chat/qwen2.5:0.5b"),
            ollama_api_base=os.getenv(
                "WARDEN_OLLAMA_API_BASE", "http://localhost:11434"
            ),
            hosted_model=os.getenv("WARDEN_HOSTED_MODEL", "openai/gpt-4o-mini"),
            hosted_api_key=os.getenv("OPENAI_API_KEY") or None,
            canary_token=os.getenv(
                "WARDEN_CANARY_TOKEN", "warden-canary-never-disclose"
            ),
            admin_api_key=os.getenv("WARDEN_ADMIN_API_KEY") or None,
        )


def create_app(
    settings: Settings | None = None,
    detectors: list[Detector] | None = None,
    llm: LLMAdapter | None = None,
    policy_store: PolicyStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    policy_store = policy_store or PolicyStore(settings.policies_path)
    llm_adapter = llm or LiteLLMAdapter(
        LLMSettings(
            ollama_model=settings.ollama_model,
            ollama_api_base=settings.ollama_api_base,
            hosted_model=settings.hosted_model,
            hosted_api_key=settings.hosted_api_key,
        )
    )
    gateway = Gateway(
        detectors=detectors
        or [
            StubAuthDetector(),
            SensitiveDataDetector(),
            PromptInjectionDetector(),
        ],
        policy_store=policy_store,
        llm=llm_adapter,
        canary_token=settings.canary_token,
    )

    app = FastAPI(title="WARDEN AI Gateway", version="0.1.0")
    app.state.gateway = gateway
    app.state.policy_store = policy_store

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest) -> ChatResponse:
        try:
            return await gateway.handle(request)
        except PolicyFileError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        except LLMUnavailableError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/policies", response_model=PolicyDocument)
    async def get_policies() -> PolicyDocument:
        try:
            return policy_store.get()
        except PolicyFileError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.put("/api/policies", response_model=PolicyDocument)
    async def put_policies(
        document: PolicyDocument,
        authorization: str | None = Header(default=None),
    ) -> PolicyDocument:
        if settings.admin_api_key is None:
            raise HTTPException(
                status_code=503,
                detail="Policy editing is disabled until WARDEN_ADMIN_API_KEY is configured.",
            )
        expected_authorization = f"Bearer {settings.admin_api_key}"
        if authorization is None or not secrets.compare_digest(
            authorization, expected_authorization
        ):
            raise HTTPException(status_code=401, detail="A valid admin bearer token is required.")
        try:
            return policy_store.put(document)
        except PolicyFileError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


app = create_app()
