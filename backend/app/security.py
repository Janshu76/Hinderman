import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt


APP_ENV = os.getenv("APP_ENV", "development")
JWT_SECRET = os.getenv(
    "JWT_SECRET", "local-development-only-change-this-secret-before-deployment"
)
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", JWT_SECRET)
if APP_ENV == "production" and (
    "JWT_SECRET" not in os.environ
    or len(JWT_SECRET) < 32
    or JWT_SECRET == "replace-with-a-long-random-local-development-secret"
):
    raise RuntimeError("Production requires a JWT_SECRET of at least 32 characters")
if APP_ENV == "production" and (
    "AUDIT_HMAC_KEY" not in os.environ
    or len(AUDIT_HMAC_KEY) < 32
    or AUDIT_HMAC_KEY == "replace-with-a-long-random-audit-hmac-key"
):
    raise RuntimeError(
        "Production requires a separate AUDIT_HMAC_KEY of at least 32 characters"
    )
if APP_ENV == "production" and (
    not os.getenv("DEMO_PASSWORD") or os.getenv("DEMO_PASSWORD") == "demo-password"
):
    raise RuntimeError("Production requires a non-demo DEMO_PASSWORD")
if APP_ENV == "production" and (
    not os.getenv("POSTGRES_PASSWORD")
    or os.getenv("POSTGRES_PASSWORD") == "local-demo-only"
):
    raise RuntimeError("Production requires a non-demo POSTGRES_PASSWORD")
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = 60
PASSWORD_ITERATIONS = 310_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, password_hash: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, password_hash)


def query_hmac(query: str) -> str:
    return hmac.new(
        AUDIT_HMAC_KEY.encode("utf-8"),
        query.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_access_token(user_id: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_TTL_MINUTES)
    return jwt.encode({"sub": user_id, "exp": expires}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise ValueError("Invalid or expired access token") from exc
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("Invalid access token subject")
    return subject
