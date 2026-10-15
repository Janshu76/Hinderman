import pytest

from backend.app.acl import can_access, chroma_acl_filter, relevant_denied_ids


@pytest.mark.parametrize(
    ("metadata", "role", "department", "clearance", "expected"),
    [
        (
            {"role_intern": True, "department": "*", "min_clearance": 0},
            "intern",
            "Engineering",
            0,
            True,
        ),
        (
            {"role_intern": True, "department": "HR", "min_clearance": 0},
            "intern",
            "Engineering",
            0,
            False,
        ),
        (
            {"role_hr_officer": True, "department": "HR", "min_clearance": 1},
            "hr_officer",
            "HR",
            2,
            True,
        ),
        (
            {
                "role_finance_manager": True,
                "department": "Finance",
                "min_clearance": 1,
            },
            "finance_manager",
            "Finance",
            2,
            True,
        ),
        (
            {
                "role_finance_manager": True,
                "department": "HR",
                "min_clearance": 1,
            },
            "finance_manager",
            "Finance",
            2,
            False,
        ),
        (
            {"role_hr_officer": True, "department": "HR", "min_clearance": 1},
            "hr_officer",
            "HR",
            0,
            False,
        ),
        (
            {"role_admin": True, "department": "Legal", "min_clearance": 3},
            "admin",
            "Operations",
            3,
            True,
        ),
    ],
)
def test_document_access(metadata, role, department, clearance, expected):
    assert can_access(metadata, role, department, clearance) is expected


def test_chroma_filter_requires_role_clearance_and_department():
    result = chroma_acl_filter("hr_officer", "HR", 2)

    assert result["$and"][0] == {"role_hr_officer": True}
    assert result["$and"][1] == {"min_clearance": {"$lte": 2}}
    assert result["$and"][2] == {
        "$or": [{"department": "*"}, {"department": "HR"}]
    }


def test_admin_filter_intentionally_spans_departments():
    result = chroma_acl_filter("admin", "Operations", 3)

    assert result == {
        "$and": [
            {"role_admin": True},
            {"min_clearance": {"$lte": 3}},
        ]
    }


def test_unknown_roles_cannot_build_acl_filters():
    with pytest.raises(ValueError, match="Unknown user role"):
        chroma_acl_filter("guest", "HR", 1)


@pytest.mark.parametrize("clearance", [None, "0", True])
def test_invalid_document_clearance_fails_closed(clearance):
    metadata = {
        "role_intern": True,
        "department": "*",
        "min_clearance": clearance,
    }

    assert not can_access(metadata, "intern", "Engineering", 0)


def test_only_relevant_denied_documents_are_reported_once():
    metadatas = [
        {
            "doc_id": "hr-salary",
            "role_hr_officer": True,
            "department": "HR",
            "min_clearance": 2,
        },
        {
            "doc_id": "hr-salary",
            "role_hr_officer": True,
            "department": "HR",
            "min_clearance": 2,
        },
    ]

    assert relevant_denied_ids(
        metadatas,
        [0.2, 0.9],
        "intern",
        "Engineering",
        0,
    ) == ["hr-salary"]
