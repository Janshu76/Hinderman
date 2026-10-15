"""Shared helpers for the red-team scenarios: log in, send a prompt, print what happened."""
from __future__ import annotations

import os

import httpx

BASE_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
PASSWORDS = {
    "intern": os.getenv("TEST_PASSWORD_INTERN", ""),
    "hr_officer": os.getenv("TEST_PASSWORD_HR", ""),
    "finance_manager": os.getenv("TEST_PASSWORD_FINANCE", ""),
    "admin": os.getenv("TEST_PASSWORD_ADMIN", ""),
}

_http = httpx.Client(base_url=BASE_URL, timeout=60)
_tokens: dict[str, str] = {}


def _token(role: str) -> str:
    if role not in _tokens:
        resp = _http.post("/api/auth/login", json={"username": role, "password": PASSWORDS[role]})
        resp.raise_for_status()
        _tokens[role] = resp.json()["access_token"]
    return _tokens[role]


def send(role: str, prompt: str, use_rag: bool = False) -> dict:
    resp = _http.post(
        "/v1/chat",
        json={"prompt": prompt, "use_rag": use_rag},
        headers={"Authorization": f"Bearer {_token(role)}"},
    )
    resp.raise_for_status()
    return resp.json()


def show(title: str, prompt: str, data: dict) -> None:
    print("=" * 72)
    print(title)
    print(f"Prompt : {prompt}")
    print(f"Action : {data['action_taken']}")
    print(f"Reply  : {data['response'][:300]}")
    report = data.get("report") or {}
    for stage in report.get("stages", []):
        print(f"  stage={stage['stage']} policy={stage.get('policy_id')} "
              f"action={stage['action']} types={stage.get('finding_types', [])}")
    if report.get("denied_doc_ids"):
        print(f"Denied documents (audit only): {report['denied_doc_ids']}")