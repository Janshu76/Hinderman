import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Approval, User
from .security import hash_password


DEMO_USERS = (
    ("intern", "Aarav Mehta", "intern", "Engineering", 0),
    ("hr_officer", "Mira Shah", "hr_officer", "HR", 2),
    ("finance_manager", "Rohan Iyer", "finance_manager", "Finance", 2),
    ("admin", "Anaya Rao", "admin", "Operations", 3),
)


def seed_database(db: Session) -> None:
    password = os.getenv("DEMO_PASSWORD", "demo-password")
    for user_id, display_name, role, department, clearance in DEMO_USERS:
        if db.get(User, user_id) is None:
            salt, password_hash = hash_password(password)
            db.add(
                User(
                    user_id=user_id,
                    display_name=display_name,
                    role=role,
                    department=department,
                    clearance=clearance,
                    password_salt=salt,
                    password_hash=password_hash,
                    active=True,
                )
            )
    db.flush()

    if db.scalar(select(Approval.approval_id).limit(1)) is None:
        db.add_all(
            [
                Approval(
                    approval_id=str(uuid.uuid4()),
                    requested_by="intern",
                    department="HR",
                    subject="Benefits eligibility summary",
                    details_redacted=(
                        "Review a request to share a role-filtered summary of "
                        "employee benefits. No personal records are attached."
                    ),
                    status="pending",
                    requested_at=datetime.now(timezone.utc),
                ),
                Approval(
                    approval_id=str(uuid.uuid4()),
                    requested_by="finance_manager",
                    department="Finance",
                    subject="Quarterly forecast export",
                    details_redacted=(
                        "Review a request to export the synthetic quarterly "
                        "forecast for the finance team."
                    ),
                    status="pending",
                    requested_at=datetime.now(timezone.utc),
                ),
            ]
        )
    db.commit()
