"""Calls the gateway for each case. Logs in as the case's role, then posts the prompt."""
from __future__ import annotations

import os
import time

import httpx

from .schema import ATTACK_GROUPS, STOP_ACTIONS, EvalCase, EvalResult

BASE_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
# Seeded test passwords come from .env. Never hard-code real ones.
PASSWORDS = {
    "intern": os.getenv("TEST_PASSWORD_INTERN", ""),
    "hr_officer": os.getenv("TEST_PASSWORD_HR", ""),
    "finance_manager": os.getenv("TEST_PASSWORD_FINANCE", ""),
    "admin": os.getenv("TEST_PASSWORD_ADMIN", ""),
}
TIMEOUT = 60.0


class GatewayClient:
    def __init__(self, base_url: str = BASE_URL) -> None:
        self.http = httpx.Client(base_url=base_url, timeout=TIMEOUT)
        self._tokens: dict[str, str] = {}

    def _token(self, role: str) -> str:
        if role not in self._tokens:
            resp = self.http.post("/api/auth/login",
                                  json={"username": role, "password": PASSWORDS[role]})
            resp.raise_for_status()
            self._tokens[role] = resp.json()["access_token"]
        return self._tokens[role]

    def run_case(self, case: EvalCase) -> EvalResult:
        headers = {"Authorization": f"Bearer {self._token(case.user_role)}",
                   "X-Eval-Run": "true"}                       # keeps the row out of the real dashboard
        body = {"prompt": case.prompt, "use_rag": case.use_rag}
        start = time.perf_counter()
        try:
            resp = self.http.post("/v1/chat", json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:                               # record the failure, never crash the run
            return _error_result(case, f"{type(exc).__name__}: {exc}")
        total_ms = int((time.perf_counter() - start) * 1000)

        action = data["action_taken"]
        found = sorted({f["type"] for f in data.get("findings_summary", [])})
        stopped = action in STOP_ACTIONS
        correct = stopped if case.is_attack else not stopped
        report = data.get("report", {})                        # present once M1 adds GatewayReport
        return EvalResult(
            case_id=case.id,
            group=case.group,
            is_attack=case.is_attack,
            action_taken=action,
            found_types=found,
            policy_ids=[s["policy_id"] for s in report.get("stages", []) if s.get("policy_id")],
            denied_doc_ids=report.get("denied_doc_ids", []),
            latency_ms={**report.get("timings_ms", {}), "total": total_ms},
            stopped=stopped,
            correct=correct,
        )


def _error_result(case: EvalCase, message: str) -> EvalResult:
    return EvalResult(case_id=case.id, group=case.group, is_attack=case.is_attack,
                      action_taken="allow", stopped=False, correct=False, error=message)