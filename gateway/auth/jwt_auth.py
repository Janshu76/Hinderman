"""JWT login and UserContext provider.

The token carries identity only (user id, issue and expiry times). Role,
department and clearance are always read from the user store, so a token can
never grant more than the store allows.

Environment:
    JWT_SECRET          required, at least 32 characters
    DEMO_USER_PASSWORD  optional password for the four seed users (demo only)
"""
import hashlib
import hmac
import os
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt

from contracts.schemas import UserContext

ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 60
TOKEN_ISSUER = "hinderman-m2"
TOKEN_AUDIENCE = "hinderman-m1-m4"
PBKDF2_ITERATIONS = 200_000
MIN_SECRET_CHARS = 32
DEFAULT_DEMO_PASSWORD = "demo-password"


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class _StoredUser:
    username: str
    context: UserContext
    salt: bytes
    password_hash: bytes
    enabled: bool = True


_SEED_USERS = (
    ("intern", "u1", "intern", "general", 0),
    ("hr", "u2", "hr_officer", "hr", 2),
    ("finance", "u3", "finance_manager", "finance", 2),
    ("admin", "u4", "admin", "it", 3),
)


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


@lru_cache(maxsize=1)
def _user_store() -> dict[str, _StoredUser]:
    password = os.environ.get("DEMO_USER_PASSWORD", DEFAULT_DEMO_PASSWORD)
    users = {}
    for username, user_id, role, department, clearance in _SEED_USERS:
        salt = os.urandom(16)
        users[user_id] = _StoredUser(
            username=username,
            context=UserContext(
                user_id=user_id, role=role, department=department, clearance=clearance
            ),
            salt=salt,
            password_hash=_hash_password(password, salt),
        )
    return users


_DUMMY_SALT = os.urandom(16)
_DUMMY_HASH = _hash_password("not-a-real-password", _DUMMY_SALT)


def _secret() -> str:
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_CHARS:
        raise RuntimeError(f"JWT_SECRET must be set and at least {MIN_SECRET_CHARS} characters")
    return secret


def authenticate(username: str, password: str) -> UserContext | None:
    """Check credentials. Does the same work whether or not the user exists."""
    match = next((u for u in _user_store().values() if u.username == username), None)
    salt, expected = (match.salt, match.password_hash) if match else (_DUMMY_SALT, _DUMMY_HASH)
    ok = hmac.compare_digest(_hash_password(password, salt), expected)
    return match.context if (match and match.enabled and ok) else None


def create_access_token(user: UserContext, ttl_minutes: int = TOKEN_TTL_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.user_id,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def login(username: str, password: str) -> str:
    user = authenticate(username, password)
    if user is None:
        raise AuthError("invalid username or password")
    return create_access_token(user)


def get_current_user(token: str) -> UserContext:
    if token.lower().startswith("bearer "):
        token = token[7:]
    try:
        claims = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError("invalid or expired token") from exc
    user_id = claims.get("sub")
    if not isinstance(user_id, str):
        raise AuthError("invalid or expired token")
    stored = _user_store().get(user_id)
    if stored is None or not stored.enabled:
        raise AuthError("unknown user")
    return stored.context


def get_user_by_id(user_id: str) -> UserContext:
    """Return an enabled user's authoritative context, never caller-supplied claims."""
    stored = _user_store().get(user_id)
    if stored is None or not stored.enabled:
        raise AuthError("unknown user")
    return stored.context


def set_user_enabled(user_id: str, enabled: bool) -> None:
    """Update a user's active status in the in-memory prototype user store."""
    users = _user_store()
    stored = users.get(user_id)
    if stored is None:
        raise AuthError("unknown user")
    users[user_id] = replace(stored, enabled=enabled)
