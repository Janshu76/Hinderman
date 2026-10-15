# Hinderman

A reverse proxy in front of the LLM, with shared contracts and M2 detection,
authentication, audit, and approval components.

## Project layout

- `contracts/`: shared Pydantic schemas and service protocols.
- `detectors/`: India-specific and generic PII, credentials, confidential
  content, inspection entry points, and the CLI.
- `gateway/auth/`: JWT authentication and the four demo seed users.
- `gateway/audit/`: HMAC/redaction helpers, SQLite-backed tamper-evident audit
  logging, and an approval queue.
- `tests/`: unit tests for contracts, detectors, authentication, and audit.
  `tests/data/pii_testset.json` contains 40 labeled India-PII prompts.

## Setup and tests

Requires Python 3.11 or newer. Install dependencies and run the full test suite:

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

## M2 authentication contract

`POST /auth/login` accepts exactly:

```json
{"username": "intern", "password": "<password>"}
```

It returns `TokenResponse`:

```json
{"access_token": "<signed JWT>", "token_type": "bearer"}
```

The M2 login endpoint currently accepts the raw JSON credentials above; it
does not require a browser bearer token. Login uses `LoginRequest` and
`TokenResponse` from `contracts.schemas` (also re-exported from `contracts`).
Invalid usernames and passwords return HTTP 401.

M2 tokens are signed with **HS256** and contain `sub` (M2 user ID), `iat`,
`exp`, `iss` (`hinderman-m2`) and `aud` (`hinderman-m1-m4`). The resolver
requires and validates all five claims, including signature, issuer and
audience; the default expiry is 60 minutes. There are no role, department or
clearance claims. Every resolution reloads the user's authoritative
`user_id`, role, department and clearance from M2's user store. Invalid,
expired, disabled or unknown users are rejected. The prototype has four seed
users (`intern`, `hr`, `finance`, `admin`) that share the configured demo
password; this in-memory seed store is for the prototype and must be replaced
with the team's production identity store before deployment.

Environment variables (set them in the process environment or a secret
manager; do not commit secret values):

- `JWT_SECRET`: required, at least 32 characters.
- `DEMO_USER_PASSWORD`: seed-user password; set explicitly for local use.
- `M2_SERVICE_TOKEN`: required for every `/internal/*` route; use a high-entropy
  service-only secret of at least 32 characters and send it using the HTTP
  Bearer authorization scheme.
- `AUDIT_HMAC_KEY`: required when the default audit logger is first used, at
  least 32 characters. M1 must use the same protected key to calculate the
  content HMAC before sending an `AuditEvent`.
- `AUDIT_HMAC_KEY_ID`: optional audit/content HMAC key identifier (default `k1`).
- `AUDIT_DB_URL`: optional SQLAlchemy database URL (default `sqlite:///audit.db`).

## M1/M4 integration

Run the service locally after exporting the environment variables above:

```powershell
$env:JWT_SECRET = "<secret of at least 32 characters>"
$env:DEMO_USER_PASSWORD = "<local demo password>"
$env:M2_SERVICE_TOKEN = "<service-to-service secret>"
$env:AUDIT_HMAC_KEY = "<audit key of at least 32 characters>"
python -m gateway.service
```

The local base URL is `http://127.0.0.1:8000`; `/health` is an unauthenticated
health check. Internal routes require the M2 service bearer token:

- `POST /internal/auth/resolve` body: `{"access_token": "<M2 JWT>"}`; returns
  the authoritative `UserContext`. Extra browser identity fields are rejected.
- `POST /internal/audit/events` body: the shared `AuditEvent`; returns
  `{"event_id": "<persisted ID>"}`.
- `POST /internal/approvals` body: `{"request_id": "...", "findings": [...],
  "redacted_snippet": "..."}`; returns an `approval_id`. Retries with the same
  request ID return the existing approval.
- `GET /internal/approvals/{approval_id}` returns the current approval status.

M1 can use `M2PlatformServicesClient` as its `PlatformServices` implementation:

```python
import os
from gateway.m2_client import M2PlatformServicesClient

platform = M2PlatformServicesClient(
    os.environ["M2_BASE_URL"],
    os.environ["M2_SERVICE_TOKEN"],
)
user = platform.get_current_user(browser_access_token)
# Use `user` (not request-body role/clearance) for policy decisions.
# Then call platform.log_event(event) and platform.enqueue_approval(...)
```

The in-process `M2PlatformServices` is available when M1 and M2 run in one
process. Both adapters implement the unchanged `PlatformServices` protocol.
M1 should construct an `AuditEvent` from the shared model, using the resolved
user ID, a pre-redacted snippet, a keyed HMAC-SHA256 of the original content,
the request ID, and any denied document IDs. The logger scrubs detected PII,
credentials and source-code markers again, truncates the snippet, and chains
each record with HMAC, and sets the persisted `prev_hash` itself (the input
`prev_hash` is retained only for schema compatibility). The hash helper is
`gateway.audit.security.compute_content_hmac(content, key_bytes)`; the
`content_sha256` field intentionally contains this HMAC, not a bare SHA-256.
The client never sends raw prompts, retrieved passages or tokens as separate
audit fields. Validation and persistence failures are returned as errors
(HTTP 4xx/5xx from the service).

**M4 handoff:** M2 JWTs are not M4-issued tokens. Do not pass frontend identity
headers or trust role/clearance submitted by the browser. M4 should either
validate M2 tokens through the authenticated `/internal/auth/resolve`
endpoint, or implement a mutually authenticated M2-to-M4 token exchange. The
intended handoff is for M4's backend to call the resolver with its service
credential and the browser's M2 access token, then apply the returned
`UserContext` in M4's server-side retrieval authorization. M4 must update its
JWT middleware to do this; an unchanged M4 endpoint that only accepts its own
JWTs will still reject M2 tokens. Do not forward browser identity headers or
treat an M2 token as an M4 token.

## Detector CLI

```powershell
python -m detectors "Contact me at person@example.com"
```

The CLI reports finding types and masked previews; it does not print the
detected raw values.
