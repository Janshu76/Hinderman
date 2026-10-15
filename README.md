# Hinderman

An AI security gateway with access-controlled RAG.

## M4 MVP

M4 owns the secure document library, retrieval, chat shell, approvals page and
security dashboard. This branch implements those pieces as a runnable
standalone prototype. The retrieval service follows the shared team contract:

```python
retrieve(query: str, user: UserContext, k: int = 4) -> RetrievalResult
```

The result contains `chunks`, `denied_count` and `denied_doc_ids`, matching
`contract/schemas.py` on the detectors branch. Access checks are applied to
ChromaDB metadata at query time; unauthorized document text is never returned.
The denied IDs are retained for the scenario/audit contract, while the UI
shows only the denied count. Retrieval audit records store a keyed HMAC-SHA256
fingerprint, not the query itself.

### Run the demo

Requirements: Docker Desktop with Docker Compose.

1. From this directory, copy `.env.example` to `.env`.
2. Start the services:

   ```powershell
   docker compose up --build
   ```

3. Open <http://localhost:5173>.
4. Sign in using one of the demo accounts. The default password is
   `demo-password` (override it in `.env` before first startup).

| User ID | Role | Department | Demo access |
| --- | --- | --- | --- |
| `intern` | Intern | Engineering | Public and Engineering documents |
| `hr_officer` | HR officer | HR | Public and HR documents |
| `finance_manager` | Finance manager | Finance | Public and Finance documents |
| `admin` | Admin | Operations | All documents |

The 19 synthetic source documents and seeded users are for demonstration
only. The document library, approvals and dashboard use the M4 backend.
The M4 `/api/rag/retrieve` endpoint applies role-based document filtering.
For standalone demo mode it validates M4-issued JWTs; when M2 settings are
configured it instead validates each M2 token through M2's trusted resolver.

### WARDEN chat integration (demo)

The Secure chat page sends prompts to WARDEN's `POST /gateway/v1/chat`
endpoint and displays its reply and gateway report. WARDEN runs separately
from this M4 stack. In the local `Hinderman-WARDEN` worktree, its Compose
configuration maps the gateway to host port `8001` and uses the installed
Ollama model `qwen3.5:4b`. Start both services with
`docker compose --project-name hinderman-warden up -d --build` from that
worktree. The M4 frontend proxy reaches `http://host.docker.internal:8001`;
set `WARDEN_URL` in `.env` if WARDEN is listening elsewhere. For `npm run
dev` outside Docker, set `WARDEN_URL` to the host URL, for example
`http://localhost:8001`.

The frontend forwards its bearer token to WARDEN. WARDEN validates the
signed-in identity through M4 `/api/auth/me`, then calls
`/api/rag/retrieve`. M4 uses M2's service-authenticated resolver when the M2
settings below are enabled, and applies the resolver's role, department, and
clearance to ACL-filtered retrieval. WARDEN scans retrieved passages with
M3's document-source injection rules before adding them as untrusted context
for the model. The response lists source document IDs, not passage contents.

### M2 authentication integration

The local Compose backend mounts `backend/app` into the container, so backend
source changes are used on container restart without rebuilding the large
retrieval image.

To enable M2 authentication, run M2's `gateway.service` on the host and
publish it on port `1234` (the local integration port), then set these values
in the M4 `.env`:

```dotenv
M2_BASE_URL=http://host.docker.internal:1234
M2_SERVICE_TOKEN=<the same service-only token configured in M2>
M2_DEPARTMENT_MAP={"general":"Engineering","hr":"HR","finance":"Finance","it":"Operations"}
```

The M4 backend proxies login to M2 `POST /auth/login`, then resolves the new
token through `POST /internal/auth/resolve`. For every protected request, M4
resolves the browser's bearer token server-to-server using
`M2_SERVICE_TOKEN`; that credential is only configured on the backend and is
never sent to the browser. Invalid tokens, resolver failures, incomplete
configuration, and invalid resolver responses fail closed. The resolver
response is the authority for user ID, role, and clearance.

`M2_DEPARTMENT_MAP` is optional trusted server configuration that translates
M2's prototype department names into the M4 document library's department
names. The sample maps `general` to `Engineering`, as well as `hr` and
`finance` to M4's `HR` and `Finance` labels. The `general` mapping is an
explicit local demo policy choice; review it before using this configuration
for another deployment. Unmapped values are preserved, which prevents them
from matching department-restricted documents accidentally. M2's admin role
already spans departments under M4's ACL rules.

Use HTTPS for `M2_BASE_URL` outside local development. Plain HTTP is accepted
only for loopback and `host.docker.internal` in development mode. If both M2
variables are empty in development, M4 retains its standalone demo JWT login;
if only one is set, authentication fails closed. Production requires both M2
settings.

### Services and stack

- **Backend:** Python 3.11, FastAPI, Uvicorn, SQLAlchemy, PostgreSQL
- **RAG:** LangChain text splitting, ChromaDB, sentence-transformers
  (`all-MiniLM-L6-v2`)
- **Frontend:** React, Vite, Tailwind CSS, Recharts
- **Authentication:** M2-issued bearer tokens resolved server-to-server;
  standalone M4 demo JWTs remain available only in local development mode
- **Deployment:** Docker Compose
- **Chat gateway:** WARDEN FastAPI service, configured separately via `WARDEN_URL`

The embedding model is downloaded by Hugging Face on first backend startup
and cached in a Docker volume.

### API

- `POST /api/auth/login` — proxy login to M2 when configured; otherwise issue
  a JWT for a seeded local demo user
- `GET /api/auth/me` — resolve the bearer token and return the trusted user
- `POST /api/rag/retrieve` — permission-filtered retrieval; response uses the
  shared `RetrievalResult` shape
- `GET /api/documents` — list only documents the caller may access
- `GET /api/incidents` and `GET /api/metrics` — privacy-safe retrieval audit
  and dashboard data
- `GET /api/approvals` and
  `PATCH /api/approvals/{approval_id}` — role-scoped approval queue
- `POST /gateway/v1/chat` — WARDEN chat with M4-authenticated retrieval
  (separate service; see above)
- `GET /health` — service health

### Configuration

Copy `.env.example` to `.env` and replace `JWT_SECRET`, `AUDIT_HMAC_KEY`,
`DEMO_PASSWORD`, and `POSTGRES_PASSWORD` before use outside a local demo.
For M2 mode also set `M2_BASE_URL` and the secret `M2_SERVICE_TOKEN` on the
M4 backend only. Do not add the service token to frontend variables. M2 tokens
have no role claims: M4 calls the resolver using its service credential for
each protected request and never trusts browser-supplied identity fields.
Keep `DATABASE_URL` in sync if you change the PostgreSQL credentials. The
example values are only suitable for local development. Do not put real
secrets or production data in the synthetic demo environment.

To run the focused backend tests outside Docker, install
`backend/requirements.txt` and run `pytest backend/tests`.
