import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.contracts import Chunk, RetrievalResult, UserContext
from backend.app.m2_client import (
    M2AuthenticationError,
    M2Client,
    M2ServiceError,
)

SERVICE_TOKEN = "local-test-service-token-with-32-chars"


class FakeM2Client:
    def __init__(
        self,
        user: UserContext | None = None,
        resolve_error: Exception | None = None,
    ) -> None:
        self.user = user or UserContext(
            user_id="m2-u2",
            role="hr_officer",
            department="HR",
            clearance=2,
        )
        self.resolve_error = resolve_error
        self.login_calls: list[tuple[str, str]] = []
        self.resolved_tokens: list[str] = []

    def login(self, username: str, password: str) -> str:
        self.login_calls.append((username, password))
        return "m2-access-token"

    def resolve_access_token(self, access_token: str) -> UserContext:
        self.resolved_tokens.append(access_token)
        if self.resolve_error is not None:
            raise self.resolve_error
        return self.user


class FakeRetriever:
    def __init__(self) -> None:
        self.users: list[UserContext] = []

    def retrieve(self, query: str, user: UserContext, k: int) -> RetrievalResult:
        self.users.append(user)
        return RetrievalResult(
            chunks=[Chunk(doc_id="hr-01", text="Synthetic HR sample", score=0.9)]
        )


class FakeDB:
    def __init__(self) -> None:
        self.rows = []

    def add(self, row) -> None:
        self.rows.append(row)

    def commit(self) -> None:
        return None


class FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeHttpxClient:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, dict, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def request(self, method, url, headers, json):
        self.requests.append((method, url, headers, json))
        return self.response


@pytest.fixture
def api_client():
    previous_overrides = main.app.dependency_overrides.copy()
    db = FakeDB()

    def fake_db():
        yield db

    main.app.dependency_overrides[main.get_db] = fake_db
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(previous_overrides)


def test_m2_login_proxies_credentials_and_returns_resolved_identity(
    api_client, monkeypatch
):
    m2 = FakeM2Client()
    monkeypatch.setattr(main, "get_m2_client", lambda: m2)

    response = api_client.post(
        "/api/auth/login",
        json={"user_id": "hr_officer", "password": "demo-password"},
    )

    assert response.status_code == 200
    assert m2.login_calls == [("hr", "demo-password")]
    assert m2.resolved_tokens == ["m2-access-token"]
    assert response.json() == {
        "access_token": "m2-access-token",
        "token_type": "bearer",
        "user": {
            "user_id": "m2-u2",
            "display_name": "HR officer",
            "role": "hr_officer",
            "department": "HR",
            "clearance": 2,
        },
    }


def test_retrieval_uses_resolver_identity_not_browser_identity(
    api_client, monkeypatch
):
    m2 = FakeM2Client()
    store = FakeRetriever()
    monkeypatch.setattr(main, "get_m2_client", lambda: m2)
    main.app.dependency_overrides[main.get_retriever] = lambda: store

    response = api_client.post(
        "/api/rag/retrieve",
        headers={"Authorization": "Bearer m2-browser-token"},
        json={"query": "salary review"},
    )

    assert response.status_code == 200
    assert m2.resolved_tokens == ["m2-browser-token"]
    assert store.users == [m2.user]
    assert response.json()["chunks"][0]["doc_id"] == "hr-01"


def test_retrieval_rejects_browser_supplied_identity_fields(api_client, monkeypatch):
    m2 = FakeM2Client()
    store = FakeRetriever()
    monkeypatch.setattr(main, "get_m2_client", lambda: m2)
    main.app.dependency_overrides[main.get_retriever] = lambda: store

    response = api_client.post(
        "/api/rag/retrieve",
        headers={"Authorization": "Bearer m2-browser-token"},
        json={
            "query": "salary review",
            "user_id": "admin",
            "role": "admin",
            "department": "Legal",
            "clearance": 3,
        },
    )

    assert response.status_code == 422
    assert store.users == []


def test_invalid_m2_token_is_rejected(api_client, monkeypatch):
    m2 = FakeM2Client(resolve_error=M2AuthenticationError("invalid token"))
    monkeypatch.setattr(main, "get_m2_client", lambda: m2)

    response = api_client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer expired-or-invalid"},
    )

    assert response.status_code == 401


def test_m2_resolver_failure_fails_closed(api_client, monkeypatch):
    m2 = FakeM2Client(resolve_error=M2ServiceError("M2 is unavailable"))
    monkeypatch.setattr(main, "get_m2_client", lambda: m2)

    response = api_client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer valid-looking-token"},
    )

    assert response.status_code == 503


def test_m2_client_uses_internal_service_auth_and_maps_departments(monkeypatch):
    fake_http = FakeHttpxClient(
        FakeResponse(
            200,
            {
                "user_id": "m2-u2",
                "role": "hr_officer",
                "department": "hr",
                "clearance": 2,
            },
        )
    )
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: fake_http)
    client = M2Client(
        "http://localhost:8002",
        SERVICE_TOKEN,
        department_map={"hr": "HR"},
    )

    resolved = client.resolve_access_token("browser-m2-token")

    assert resolved == UserContext(
        user_id="m2-u2",
        role="hr_officer",
        department="HR",
        clearance=2,
    )
    assert fake_http.requests == [
        (
            "POST",
            "http://localhost:8002/internal/auth/resolve",
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {SERVICE_TOKEN}",
            },
            {"access_token": "browser-m2-token"},
        )
    ]


def test_m2_client_rejects_insecure_nonlocal_urls():
    with pytest.raises(M2ServiceError, match="HTTPS"):
        M2Client(
            "http://m2.example.com",
            SERVICE_TOKEN,
        )


def test_m2_client_rejects_resolver_unauthorized_response(monkeypatch):
    fake_http = FakeHttpxClient(FakeResponse(401, {"detail": "unauthorized"}))
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: fake_http)
    client = M2Client("http://localhost:8002", SERVICE_TOKEN)

    with pytest.raises(M2AuthenticationError):
        client.resolve_access_token("expired-token")
