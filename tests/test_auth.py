import pytest

from contracts.schemas import UserContext
from gateway.auth import jwt_auth


@pytest.fixture(autouse=True)
def auth_environment(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret-that-is-long-enough-123456")
    monkeypatch.setenv("DEMO_USER_PASSWORD", "test-demo-password-123")
    jwt_auth._user_store.cache_clear()
    yield
    jwt_auth._user_store.cache_clear()


def test_seed_users_authenticate_with_shared_demo_password():
    expected = {
        "intern": ("u1", "intern", "general", 0),
        "hr": ("u2", "hr_officer", "hr", 2),
        "finance": ("u3", "finance_manager", "finance", 2),
        "admin": ("u4", "admin", "it", 3),
    }
    for username, details in expected.items():
        user = jwt_auth.authenticate(username, "test-demo-password-123")
        assert isinstance(user, UserContext)
        assert (user.user_id, user.role, user.department, user.clearance) == details


def test_wrong_username_or_password_does_not_authenticate():
    assert jwt_auth.authenticate("unknown", "test-demo-password-123") is None
    assert jwt_auth.authenticate("intern", "wrong-password") is None


def test_login_and_get_current_user_round_trip():
    token = jwt_auth.login("admin", "test-demo-password-123")
    user = jwt_auth.get_current_user(token)
    assert (user.user_id, user.role) == ("u4", "admin")


def test_get_current_user_accepts_bearer_prefix():
    token = jwt_auth.login("hr", "test-demo-password-123")
    user = jwt_auth.get_current_user("Bearer " + token)
    assert user.user_id == "u2"


def test_invalid_login_raises_auth_error():
    with pytest.raises(jwt_auth.AuthError, match="invalid username or password"):
        jwt_auth.login("admin", "incorrect")


def test_missing_or_short_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(RuntimeError, match="at least 32"):
        jwt_auth.login("intern", "test-demo-password-123")


def test_expired_token_is_rejected():
    user = jwt_auth.authenticate("intern", "test-demo-password-123")
    token = jwt_auth.create_access_token(user, ttl_minutes=-1)
    with pytest.raises(jwt_auth.AuthError, match="invalid or expired token"):
        jwt_auth.get_current_user(token)


def test_malformed_token_is_rejected():
    with pytest.raises(jwt_auth.AuthError, match="invalid or expired token"):
        jwt_auth.get_current_user("not.a.valid.token")
