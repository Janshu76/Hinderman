import json
import os
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from .contracts import UserContext

MIN_SERVICE_TOKEN_CHARS = 32
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


class M2ServiceError(RuntimeError):
    pass


class M2AuthenticationError(M2ServiceError):
    pass


class M2ConfigurationError(M2ServiceError):
    pass


class M2Client:
    def __init__(
        self,
        base_url: str,
        service_token: str,
        department_map: dict[str, str] | None = None,
        app_env: str = "development",
        timeout: float = 5.0,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if (
            parsed_url.scheme not in ("http", "https")
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise M2ConfigurationError(
                "M2_BASE_URL must be an absolute HTTP(S) URL without credentials, query, or fragment."
            )
        if parsed_url.scheme != "https" and (
            app_env == "production" or parsed_url.hostname not in LOCAL_HOSTS
        ):
            raise M2ConfigurationError(
                "M2_BASE_URL must use HTTPS outside local development."
            )
        if len(service_token) < MIN_SERVICE_TOKEN_CHARS:
            raise M2ConfigurationError(
                f"M2_SERVICE_TOKEN must be at least {MIN_SERVICE_TOKEN_CHARS} characters."
            )
        if department_map is not None and any(
            not isinstance(source, str)
            or not source
            or not isinstance(target, str)
            or not target
            for source, target in department_map.items()
        ):
            raise M2ConfigurationError(
                "M2_DEPARTMENT_MAP must map non-empty department names to non-empty department names."
            )

        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.department_map = department_map or {}
        self.timeout = timeout

    def login(self, username: str, password: str) -> str:
        result = self._request(
            "POST",
            "/auth/login",
            json={"username": username, "password": password},
            service_auth=False,
        )
        access_token = result.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise M2ServiceError("M2 returned an invalid login response.")
        if result.get("token_type", "bearer") != "bearer":
            raise M2ServiceError("M2 returned an unsupported token type.")
        return access_token

    def resolve_access_token(self, access_token: str) -> UserContext:
        result = self._request(
            "POST",
            "/internal/auth/resolve",
            json={"access_token": access_token},
            service_auth=True,
        )
        try:
            context = UserContext.model_validate(result)
        except ValidationError as exc:
            raise M2ServiceError("M2 returned an invalid user context.") from exc

        canonical_department = self.department_map.get(
            context.department, context.department
        )
        return context.model_copy(update={"department": canonical_department})

    def _request(
        self,
        method: str,
        path: str,
        json: dict[str, str],
        service_auth: bool,
    ) -> dict:
        headers = {"Accept": "application/json"}
        if service_auth:
            headers["Authorization"] = f"Bearer {self.service_token}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=headers,
                    json=json,
                )
        except httpx.RequestError as exc:
            raise M2ServiceError("M2 authentication service is unavailable.") from exc

        if response.status_code == 401:
            raise M2AuthenticationError("M2 rejected the supplied credentials.")
        if response.status_code != 200:
            raise M2ServiceError(
                f"M2 authentication service returned HTTP {response.status_code}."
            )
        try:
            result = response.json()
        except ValueError as exc:
            raise M2ServiceError("M2 returned an invalid response.") from exc
        if not isinstance(result, dict):
            raise M2ServiceError("M2 returned an invalid response.")
        return result


def get_m2_client() -> M2Client | None:
    base_url = os.getenv("M2_BASE_URL", "").strip()
    service_token = os.getenv("M2_SERVICE_TOKEN", "")
    app_env = os.getenv("APP_ENV", "development").strip().lower()

    if not base_url and not service_token:
        if app_env == "production":
            raise M2ConfigurationError(
                "M2_BASE_URL and M2_SERVICE_TOKEN are required in production."
            )
        return None
    if not base_url or not service_token:
        raise M2ConfigurationError(
            "M2_BASE_URL and M2_SERVICE_TOKEN must be configured together."
        )

    raw_department_map = os.getenv("M2_DEPARTMENT_MAP", "").strip()
    if raw_department_map:
        try:
            department_map = json.loads(raw_department_map)
        except json.JSONDecodeError as exc:
            raise M2ConfigurationError(
                "M2_DEPARTMENT_MAP must be a JSON object."
            ) from exc
        if not isinstance(department_map, dict):
            raise M2ConfigurationError(
                "M2_DEPARTMENT_MAP must be a JSON object."
            )
    else:
        department_map = {}

    return M2Client(
        base_url=base_url,
        service_token=service_token,
        department_map=department_map,
        app_env=app_env,
    )
