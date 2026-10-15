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

Try “What is the CFO's salary?” as `intern`, then as `hr_officer`. The intern
receives no HR content and the denied attempt appears in the dashboard.

The 19 synthetic source documents and seeded users are for demonstration
only. The chat shell displays authorized retrieved passages; it does not
generate a natural-language answer. LLM generation and the full gateway
pipeline are integration points owned by the other team members.

### Services and stack

- **Backend:** Python 3.11, FastAPI, Uvicorn, SQLAlchemy, PostgreSQL
- **RAG:** LangChain text splitting, ChromaDB, sentence-transformers
  (`all-MiniLM-L6-v2`)
- **Frontend:** React, Vite, Tailwind CSS, Recharts
- **Authentication:** JWT demo login, with role/department/clearance loaded
  from PostgreSQL for every request
- **Deployment:** Docker Compose

The embedding model is downloaded by Hugging Face on first backend startup
and cached in a Docker volume.

### API

- `POST /api/auth/login` — issue a JWT for a seeded demo user
- `GET /api/auth/me` — validate the JWT and return the current user
- `POST /api/rag/retrieve` — permission-filtered retrieval; response uses the
  shared `RetrievalResult` shape
- `GET /api/documents` — list only documents the caller may access
- `GET /api/incidents` and `GET /api/metrics` — privacy-safe retrieval audit
  and dashboard data
- `GET /api/approvals` and
  `PATCH /api/approvals/{approval_id}` — role-scoped approval queue
- `GET /health` — service health

### Configuration

Copy `.env.example` to `.env` and replace `JWT_SECRET`, `AUDIT_HMAC_KEY`,
`DEMO_PASSWORD`, and `POSTGRES_PASSWORD` before use outside a local demo.
Keep `DATABASE_URL` in sync if you change the PostgreSQL credentials. The
example values are only suitable for local development. Do not put real
secrets or production data in the synthetic demo environment.

To run the focused backend tests outside Docker, install
`backend/requirements.txt` and run `pytest backend/tests`.
