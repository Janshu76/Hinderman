import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .contracts import RetrievalResult, UserContext
from .database import Base, SessionLocal, engine, get_db
from .models import Approval, RetrievalIncident, User
from .retriever import AccessControlledRetriever
from .security import (
    create_access_token,
    decode_access_token,
    query_hmac,
    verify_password,
)
from .seed import seed_database


ROOT = Path(__file__).resolve().parent.parent
CHROMA_PATH = os.getenv("CHROMA_PATH", str(ROOT / "chroma-data"))
DOCUMENTS_PATH = ROOT / "data" / "documents.json"
retriever: AccessControlledRetriever | None = None
bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserResponse(BaseModel):
    user_id: str
    display_name: str
    role: str
    department: str
    clearance: int


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserResponse


class RetrievalRequest(BaseModel):
    query: str = Field(min_length=1, max_length=10_000)
    k: int = Field(default=4, ge=1, le=8)


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]


class ApprovalResponse(BaseModel):
    approval_id: str
    requested_by: str
    department: str
    subject: str
    details_redacted: str
    status: str
    decided_by: str | None
    requested_at: datetime
    decided_at: datetime | None


def user_response(user: User) -> UserResponse:
    return UserResponse(
        user_id=user.user_id,
        display_name=user.display_name,
        role=user.role,
        department=user.department,
        clearance=user.clearance,
    )


def approval_response(approval: Approval) -> ApprovalResponse:
    return ApprovalResponse(
        approval_id=approval.approval_id,
        requested_by=approval.requested_by,
        department=approval.department,
        subject=approval.subject,
        details_redacted=approval.details_redacted,
        status=approval.status,
        decided_by=approval.decided_by,
        requested_at=approval.requested_at,
        decided_at=approval.decided_at,
    )


def incident_scope(query, user: UserContext):
    if user.role == "admin":
        return query
    if user.role in ("hr_officer", "finance_manager"):
        return query.where(RetrievalIncident.user_department == user.department)
    return query.where(RetrievalIncident.user_id == user.user_id)


def approval_scope(query, user: UserContext):
    if user.role == "admin":
        return query
    return query.where(Approval.department == user.department)


def require_approver(user: UserContext) -> None:
    if user.role == "intern":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only department approvers can decide approval requests",
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    global retriever
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db)
    retriever = AccessControlledRetriever(CHROMA_PATH, DOCUMENTS_PATH)
    yield
    retriever = None


app = FastAPI(
    title="Hinderman M4 RAG API",
    description="Access-controlled document retrieval and dashboard services.",
    version="0.1.0",
    lifespan=lifespan,
)

origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> UserContext:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user_id = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.get(User, user_id)
    if user is None or not user.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive or no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return UserContext(
        user_id=user.user_id,
        role=user.role,
        department=user.department,
        clearance=user.clearance,
    )


def get_retriever() -> AccessControlledRetriever:
    if retriever is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document retrieval is not ready",
        )
    return retriever


@app.get("/health")
def health(store: AccessControlledRetriever = Depends(get_retriever)):
    return {"status": "ok", "indexed_chunks": store.collection.count()}


@app.post("/api/auth/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.get(User, request.user_id)
    if (
        user is None
        or not user.active
        or not verify_password(request.password, user.password_salt, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID or password",
        )
    return LoginResponse(
        access_token=create_access_token(user.user_id),
        user=user_response(user),
    )


@app.get("/api/auth/me", response_model=UserResponse)
def current_user(
    user_context: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_context.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user_response(user)


@app.post("/api/rag/retrieve", response_model=RetrievalResult)
def retrieve(
    request: RetrievalRequest,
    user: UserContext = Depends(get_current_user),
    store: AccessControlledRetriever = Depends(get_retriever),
    db: Session = Depends(get_db),
):
    result = store.retrieve(request.query, user, request.k)
    db.add(
        RetrievalIncident(
            id=str(uuid.uuid4()),
            user_id=user.user_id,
            user_department=user.department,
            query_hmac_sha256=query_hmac(request.query),
            denied_count=result.denied_count,
            denied_doc_ids=json.dumps(result.denied_doc_ids),
            created_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    return result


@app.get("/api/documents")
def list_documents(
    user: UserContext = Depends(get_current_user),
    store: AccessControlledRetriever = Depends(get_retriever),
):
    return {"documents": store.list_accessible_documents(user)}


@app.get("/api/incidents")
def list_incidents(
    limit: int = 30,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
    query = incident_scope(select(RetrievalIncident), user)
    rows = db.scalars(
        query.order_by(RetrievalIncident.created_at.desc()).limit(limit)
    ).all()
    return {
        "incidents": [
            {
                "id": row.id,
                "user_id": row.user_id,
                "user_department": row.user_department,
                "event": "Restricted document access denied"
                if row.denied_count
                else "Authorized retrieval",
                "denied_count": row.denied_count,
                "denied_doc_ids": json.loads(row.denied_doc_ids),
                "created_at": row.created_at,
            }
            for row in rows
        ]
    }


@app.get("/api/metrics")
def metrics(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = incident_scope(select(RetrievalIncident), user)
    rows = db.scalars(query.order_by(RetrievalIncident.created_at.desc())).all()
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=6)).date()
    day_counts: dict[str, int] = {}
    for offset in range(7):
        date_key = (start + timedelta(days=offset)).isoformat()
        day_counts[date_key] = 0

    users_query = select(User)
    if user.role in ("hr_officer", "finance_manager"):
        users_query = users_query.where(User.department == user.department)
    elif user.role != "admin":
        users_query = users_query.where(User.user_id == user.user_id)
    user_stats: dict[str, dict[str, int | str]] = {
        visible_user.user_id: {
            "user_id": visible_user.user_id,
            "department": visible_user.department,
            "total_requests": 0,
            "denied_requests": 0,
        }
        for visible_user in db.scalars(users_query).all()
    }
    denied_requests = 0
    denied_documents = 0
    for row in rows:
        created = row.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        date_key = created.date().isoformat()
        if date_key in day_counts:
            day_counts[date_key] += 1
        is_denied = row.denied_count > 0
        denied_requests += int(is_denied)
        denied_documents += row.denied_count
        stats = user_stats.setdefault(
            row.user_id,
            {
                "user_id": row.user_id,
                "department": row.user_department,
                "total_requests": 0,
                "denied_requests": 0,
            },
        )
        stats["total_requests"] = int(stats["total_requests"]) + 1
        stats["denied_requests"] = int(stats["denied_requests"]) + int(is_denied)

    risk_rows = []
    for stats in user_stats.values():
        total = int(stats["total_requests"])
        denied = int(stats["denied_requests"])
        risk_rows.append(
            {
                **stats,
                "risk_score": round(100 * denied / total) if total else 0,
            }
        )
    risk_rows.sort(key=lambda item: (-item["risk_score"], item["user_id"]))

    return {
        "total_requests": len(rows),
        "denied_requests": denied_requests,
        "denied_documents": denied_documents,
        "incidents_over_time": [
            {"date": key, "count": count} for key, count in day_counts.items()
        ],
        "category_breakdown": [
            {"category": "Restricted documents", "count": denied_documents},
            {
                "category": "Authorized retrievals",
                "count": len(rows) - denied_requests,
            },
        ],
        "top_policies": [
            {
                "policy": "Department, role and clearance ACL",
                "count": denied_requests,
            }
        ],
        "per_user_risk": risk_rows,
        "recent_incidents": [
            {
                "id": row.id,
                "user_id": row.user_id,
                "department": row.user_department,
                "denied_count": row.denied_count,
                "event": "Restricted document access denied"
                if row.denied_count
                else "Authorized retrieval",
                "created_at": row.created_at,
            }
            for row in rows[:8]
        ],
    }


@app.get("/api/approvals", response_model=list[ApprovalResponse])
def list_approvals(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = approval_scope(select(Approval), user)
    rows = db.scalars(query.order_by(Approval.requested_at.desc())).all()
    return [approval_response(row) for row in rows]


@app.patch(
    "/api/approvals/{approval_id}",
    response_model=ApprovalResponse,
)
def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_approver(user)
    query = approval_scope(select(Approval), user).where(
        Approval.approval_id == approval_id
    )
    approval = db.scalar(query)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail="Approval has already been decided")

    approval.status = request.decision
    approval.decided_by = user.user_id
    approval.decided_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(approval)
    return approval_response(approval)
