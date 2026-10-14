# WARDEN

WARDEN is a policy-driven AI traffic gateway. It accepts chat requests, runs
detectors concurrently, picks one action from YAML policy, applies the action,
calls an LLM, and returns a gateway report alongside the reply.

## Run locally

Requires Python 3.11 or newer and an Ollama server with `qwen2.5:0.5b` pulled.
For local development:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
ollama pull qwen2.5:0.5b
$env:WARDEN_OLLAMA_MODEL = "ollama_chat/qwen2.5:0.5b"
$env:WARDEN_OLLAMA_API_BASE = "http://localhost:11434"
py -m uvicorn warden.main:app --reload
```

If the Ollama request fails, WARDEN uses `WARDEN_HOSTED_MODEL` (default
`openai/gpt-4o-mini`) when `OPENAI_API_KEY` is set. Without a configured hosted
key, an unavailable LLM is reported as an HTTP 502 rather than a fake success.
To enable policy editing, set `WARDEN_ADMIN_API_KEY` before launching the
server; without it, the policy write endpoint is disabled. Supply a long,
unique value in any non-demo deployment.

## One-command Docker demo

Requires Docker Compose. From the project root:

```powershell
docker compose up --build
```

Compose starts Ollama, pulls the small demo model, then starts the gateway on
`http://localhost:8000`. The initial model download can take a few minutes.
To enable hosted fallback, set `OPENAI_API_KEY` in the shell before starting
Compose. API docs are at `http://localhost:8000/docs`.

Run the scripted demo in a second PowerShell window:

```powershell
.\scripts\demo.ps1
```

The script sends a normal prompt, then a prompt containing an email address,
changes the email policy from masking to blocking through the API, and repeats
the request to show that the live policy update takes effect immediately. The
Compose demo configures `WARDEN_ADMIN_API_KEY=warden-demo-admin-key` by default;
override it for any shared environment.

## API

`POST /v1/chat` accepts user/assistant messages and returns `reply` plus
`gateway_report` (selected action, policy reason, findings without matched
sensitive values, affected-item count, model/fallback status, and latency).
Client-provided system messages are rejected. `GET /health` is a liveness check.

`GET /api/policies` returns the active policy document.
`PUT /api/policies` validates and atomically saves a replacement document.
Policy writes require `Authorization: Bearer <WARDEN_ADMIN_API_KEY>` and return
HTTP 503 when no admin key is configured.
The policy store checks the policy file contents on each request, so manual
edits to `config/policies.yaml` are picked up without a process restart. Keep write
access to this API restricted to trusted operators when deploying outside the
local demo.

Example request:

```json
{
  "user_id": "demo",
  "messages": [{"role": "user", "content": "What does WARDEN do?"}]
}
```

## Policies

`config/policies.yaml` is ordered for readability; selection is based on highest
finding severity first, then rule priority, then action precedence (block,
redact, mask, warn, allow). A rule matches its category (or `*`) when the
finding severity is at least `min_severity`. The highest-ranked matching rule
selects the single action for the request.

```yaml
version: 1
rules:
  - category: email
    min_severity: low
    action: mask
    priority: 10
  - category: prompt_injection
    min_severity: high
    action: block
    priority: 90
```

Supported actions are `allow`, `warn`, `mask`, `redact`, and `block`. `mask`
replaces detected values with `***`; `redact` uses the rule's `replacement`;
`block` does not call the LLM; `warn` permits the LLM call and prefixes the
reply with the policy warning. The selected mask or redact action is applied to
all findings that matched enabled rules for the request, so a second detected
value cannot accidentally pass through because another rule selected the
request-wide action. For redact, the selected rule's replacement is applied to
each matched value. API edits should send the complete document.

## Extending detectors and integrations

Detectors implement the async `detect(user_id, messages)` interface and are run
with `asyncio.gather`. Replace `StubAuthDetector` with the real authentication
module, `ConsoleAuditLogger` with the audit service, and the demo regex
detectors with production detector modules when those integrations are
available. These demo detectors are intentionally simple signatures and are
not a production-grade DLP or prompt-injection classifier. The canary is passed
in a guarded system prompt and a separate output guard blocks responses that
contain its configured token. Since conversation roles are client-supplied,
the demo sensitive-data and prompt-injection detectors inspect all submitted
messages, including assistant history.

## Tests

```powershell
py -m pip install -e ".[dev]"
py -m pytest
```
