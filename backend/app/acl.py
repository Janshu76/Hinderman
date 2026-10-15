from collections.abc import Mapping
from typing import Any


ROLES = ("intern", "hr_officer", "finance_manager", "admin")


def chroma_acl_filter(role: str, department: str, clearance: int) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError("Unknown user role")

    filters: list[dict[str, Any]] = [
        {f"role_{role}": True},
        {"min_clearance": {"$lte": clearance}},
    ]
    if role != "admin":
        filters.append(
            {
                "$or": [
                    {"department": "*"},
                    {"department": department},
                ]
            }
        )
    return {"$and": filters}


def can_access(
    metadata: Mapping[str, Any], role: str, department: str, clearance: int
) -> bool:
    required_clearance = metadata.get("min_clearance")
    return (
        role in ROLES
        and metadata.get(f"role_{role}") is True
        and (role == "admin" or metadata.get("department") in ("*", department))
        and isinstance(required_clearance, int)
        and not isinstance(required_clearance, bool)
        and required_clearance <= clearance
    )


def relevant_denied_ids(
    metadatas: list[Mapping[str, Any]],
    distances: list[float],
    role: str,
    department: str,
    clearance: int,
    max_distance: float = 0.65,
) -> list[str]:
    denied_ids: list[str] = []
    for metadata, distance in zip(metadatas, distances, strict=True):
        doc_id = str(metadata["doc_id"])
        if (
            distance <= max_distance
            and not can_access(metadata, role, department, clearance)
            and doc_id not in denied_ids
        ):
            denied_ids.append(doc_id)
    return denied_ids
