import os
import secrets
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import ValidationError

from warden.detectors import (
    Detector,
    InjectionScorerDetector,
    SensitiveDataDetector,
    StubAuthDetector,
)
from warden.gateway import Gateway
from warden.llm import (
    LLMAdapter,
    LLMSettings,
    LLMUnavailableError,
    OllamaHTTPAdapter,
)
from warden.models import (
    ChatRequest,
    ChatResponse,
    Finding,
    PolicyDocument,
    RetrievedChunk,
)
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
    m4_api_base_url: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            policies_path=Path(
                os.getenv("WARDEN_POLICIES_PATH", "config/policies.yaml")
            ),
            ollama_model=os.getenv("WARDEN_OLLAMA_MODEL", "ollama_chat/qwen3.5:4b"),
            ollama_api_base=os.getenv(
                "WARDEN_OLLAMA_API_BASE", "http://localhost:11434"
            ),
            hosted_model=os.getenv("WARDEN_HOSTED_MODEL", "openai/gpt-4o-mini"),
            hosted_api_key=os.getenv("OPENAI_API_KEY") or None,
            canary_token=os.getenv(
                "WARDEN_CANARY_TOKEN", "warden-canary-never-disclose"
            ),
            admin_api_key=os.getenv("WARDEN_ADMIN_API_KEY") or None,
            m4_api_base_url=os.getenv("M4_API_BASE_URL") or None,
        )


def create_app(
    settings: Settings | None = None,
    detectors: list[Detector] | None = None,
    llm: LLMAdapter | None = None,
    policy_store: PolicyStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    policy_store = policy_store or PolicyStore(settings.policies_path)
    llm_adapter = llm or OllamaHTTPAdapter(
        LLMSettings(
            ollama_model=settings.ollama_model,
            ollama_api_base=settings.ollama_api_base,
            hosted_model=settings.hosted_model,
            hosted_api_key=settings.hosted_api_key,
        )
    )
    default_detectors: list[Detector] = [
        SensitiveDataDetector(),
        InjectionScorerDetector(),
    ]
    if settings.m4_api_base_url is None:
        default_detectors.insert(0, StubAuthDetector())
    gateway = Gateway(
        detectors=detectors or default_detectors,
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

    @app.post("/gateway/v1/chat", response_model=ChatResponse)
    async def chat(
        request: ChatRequest,
        authorization: str | None = Header(default=None),
    ) -> ChatResponse:
        try:
            if settings.m4_api_base_url is None:
                return await gateway.handle(request)

            if authorization is None or not authorization.lower().startswith("bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="A valid M4 bearer token is required.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            headers = {"Authorization": authorization}
            base_url = settings.m4_api_base_url.rstrip("/")
            async with httpx.AsyncClient(timeout=30) as client:
                identity_response = await client.get(
                    f"{base_url}/api/auth/me", headers=headers
                )
                if identity_response.status_code == 401:
                    raise HTTPException(status_code=401, detail="M4 authentication failed.")
                if identity_response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail="M4 could not verify the signed-in user.",
                    )
                try:
                    identity = identity_response.json()
                    trusted_user_id = identity["user_id"]
                except (ValueError, KeyError, TypeError) as exc:
                    raise HTTPException(
                        status_code=502,
                        detail="M4 returned an invalid identity response.",
                    ) from exc

                query = next(
                    (
                        message.content
                        for message in reversed(request.messages)
                        if message.role == "user"
                    ),
                    None,
                )
                if query is None:
                    raise HTTPException(
                        status_code=422,
                        detail="A user message is required for retrieval.",
                    )
                retrieval_response = await client.post(
                    f"{base_url}/api/rag/retrieve",
                    headers=headers,
                    json={"query": query, "k": 4},
                )
                if retrieval_response.status_code == 401:
                    raise HTTPException(status_code=401, detail="M4 authentication failed.")
                if retrieval_response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail="M4 document retrieval failed.",
                    )
                try:
                    payload = retrieval_response.json()
                    chunks = [
                        RetrievedChunk.model_validate(chunk)
                        for chunk in payload["chunks"]
                    ]
                except (ValueError, KeyError, TypeError, ValidationError) as exc:
                    raise HTTPException(
                        status_code=502,
                        detail="M4 returned an invalid retrieval response.",
                    ) from exc

            scorer = next(
                (
                    detector
                    for detector in gateway.detectors
                    if isinstance(detector, InjectionScorerDetector)
                ),
                None,
            )
            document_findings = (
                await scorer.detect_documents([chunk.text for chunk in chunks])
                if scorer is not None
                else []
            )
            authenticated_request = request.model_copy(
                update={"user_id": trusted_user_id}
            )
            return await gateway.handle(
                authenticated_request,
                retrieved_chunks=chunks,
                document_findings=document_findings,
                trusted_user_id=trusted_user_id,
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=503,
                detail="WARDEN could not reach the M4 authentication or retrieval service.",
            ) from exc
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
            raise HTTPException(
                status_code=401, detail="A valid admin bearer token is required."
            )
        try:
            return policy_store.put(document)
        except PolicyFileError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


app = create_app()
