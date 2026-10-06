import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def token(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, html[:300]
    return match.group(1)


@pytest.fixture
def negative_workspace(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'negative.db'}",
        admin_password="negative-password",
        session_secret="negative-test-session-secret-at-least-32-characters",
        max_upload_bytes=16,
        secure_cookies=False,
    )
    app = create_app(settings)
    # Negative tests must receive a 5xx response instead of re-raising a server
    # exception into pytest; that makes accidental 500s explicit assertions.
    with TestClient(app, follow_redirects=False, raise_server_exceptions=False) as client:
        login = client.get("/login")
        response = client.post(
            "/login", data={"username": "admin", "password": settings.admin_password, "csrf": token(login.text)}
        )
        assert response.status_code == 303
        yield client, token(client.get("/").text), tmp_path


def program(client: TestClient, csrf: str, name: str = "Program", *, archived: bool = False) -> str:
    response = client.post(
        "/programs/new",
        data={
            "csrf": csrf,
            "name": name,
            "platform": "HackerOne",
            "url": "",
            "handle": name.lower().replace(" ", "-"),
            "notes": "",
            "archived": str(archived).lower(),
        },
    )
    assert response.status_code == 303, response.text
    return response.headers["location"].rsplit("/", 1)[-1]


def knowledge(client: TestClient, csrf: str, title: str = "Knowledge", **extra) -> str:
    data = {
        "csrf": csrf,
        "title": title,
        "bug_type": "XSS",
        "default_severity": "high",
        "summary": "Summary",
        "endpoint": "GET /",
        "technology": "FastAPI",
        "cwe": "CWE-79",
        "cvss_score": "7.5",
        "research_notes": "",
        "program_id": "",
        "finding_id": "",
        "finding_target": "",
        "finding_scope": "",
        "finding_status": "draft",
        "finding_report_id": "",
        "finding_report_url": "",
        "finding_discovered_at": "",
        "finding_submitted_at": "",
        "finding_private_notes": "",
        "related_ids": [],
        "markdown": "# Report\n\nBody.",
        "remediation": "Fix.",
        "references": "",
    }
    data.update(extra)
    response = client.post("/knowledge/new", data=data)
    assert response.status_code == 303, response.text
    return response.headers["location"].split("?", 1)[0].rsplit("/", 1)[-1]


def finding(client: TestClient, csrf: str, program_id: str, knowledge_id: str, **extra) -> tuple[str, object]:
    data = {
        "csrf": csrf,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "target": "api.example.com",
        "scope": "Web",
        "status": "submitted",
        "severity": "high",
        "report_id": "H1-1",
        "report_url": "",
        "discovered_at": "2026-01-01",
        "submitted_at": "2026-01-02",
        "private_notes": "",
        "triaged_at": "",
        "resolved_at": "",
        "rewarded_at": "",
        "payout": "",
        "bonus": "",
        "currency": "USD",
        "program_severity": "",
        "duplicate_of": "",
    }
    data.update(extra)
    response = client.post("/findings/new", data=data)
    location = response.headers.get("location", "")
    finding_id = location.split("finding_id=")[-1] if "finding_id=" in location else ""
    return finding_id, response


def test_wrong_password_does_not_create_a_session(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'auth.db'}",
        admin_password="correct-password",
        session_secret="auth-test-secret-at-least-32-characters",
        max_upload_bytes=1024,
        secure_cookies=False,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        login = client.get("/login")
        response = client.post(
            "/login", data={"username": "admin", "password": "wrong-password", "csrf": token(login.text)}
        )
        assert response.status_code == 401
        assert client.get("/").status_code == 303
        assert client.get("/").headers["location"] == "/login"


def test_logout_requires_csrf_and_clears_session(negative_workspace):
    client, csrf, _ = negative_workspace
    assert client.post("/logout", data={"csrf": "invalid"}).status_code == 403
    assert client.get("/").status_code == 200
    assert client.post("/logout", data={"csrf": csrf}).status_code == 303
    assert client.get("/").status_code == 303


def test_mutation_families_reject_invalid_csrf(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    knowledge_id = knowledge(client, csrf)
    finding_id, created = finding(client, csrf, program_id, knowledge_id)
    assert created.status_code == 303

    checks = [
        client.post("/programs/new", data={"csrf": "bad", "name": "Nope"}),
        client.post(f"/programs/{program_id}/archive", data={"csrf": "bad"}),
        client.post("/capture", data={"csrf": "bad", "title": "Nope", "capture": "x"}),
        client.post("/markdown/preview", data={"csrf": "bad", "markdown": "# x"}),
        client.post(f"/findings/{finding_id}/move", data={"csrf": "bad", "program_id": program_id}),
        client.post(f"/knowledge/{knowledge_id}/delete", data={"csrf": "bad"}),
    ]
    assert [response.status_code for response in checks] == [403] * len(checks)
    assert client.get(f"/knowledge/{knowledge_id}").status_code == 200


def test_blank_and_duplicate_program_names_are_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    assert client.post("/programs/new", data={"csrf": csrf, "name": "   "}).status_code == 422
    unique_id = program(client, csrf, "Unique Program")
    duplicate = client.post("/programs/new", data={"csrf": csrf, "name": "unique program"})
    assert duplicate.status_code == 409

    other_id = program(client, csrf, "Other Program")
    rename_collision = client.post(
        f"/programs/{other_id}/edit",
        data={
            "csrf": csrf,
            "name": "Unique Program",
            "platform": "",
            "url": "",
            "handle": "",
            "notes": "",
        },
    )
    assert rename_collision.status_code == 409
    assert client.get(f"/programs/{unique_id}").status_code == 200


def test_blank_knowledge_title_is_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "  ",
            "bug_type": "XSS",
            "default_severity": "high",
        },
    )
    assert response.status_code == 422


def test_duplicate_finding_link_is_rejected_on_create_and_edit(negative_workspace):
    client, csrf, _ = negative_workspace
    first_program = program(client, csrf, "First")
    second_program = program(client, csrf, "Second")
    entry = knowledge(client, csrf)
    first_id, first = finding(client, csrf, first_program, entry)
    assert first.status_code == 303
    _second_id, duplicate = finding(client, csrf, first_program, entry)
    assert duplicate.status_code == 409

    second_id, second = finding(client, csrf, second_program, entry)
    assert second.status_code == 303
    collision = client.post(
        f"/findings/{second_id}/edit",
        data={
            "csrf": csrf,
            "program_id": first_program,
            "knowledge_id": entry,
            "target": "x",
            "scope": "",
            "status": "submitted",
            "severity": "high",
            "submitted_at": "2026-01-02",
        },
    )
    assert collision.status_code == 409
    assert first_id != second_id


def test_archived_program_rejects_new_and_moved_findings(negative_workspace):
    client, csrf, _ = negative_workspace
    archived = program(client, csrf, "Archived", archived=True)
    active = program(client, csrf, "Active")
    entry = knowledge(client, csrf)
    _unused, rejected = finding(client, csrf, archived, entry)
    assert rejected.status_code == 422

    finding_id, created = finding(client, csrf, active, entry)
    assert created.status_code == 303
    moved = client.post(f"/findings/{finding_id}/move", data={"csrf": csrf, "program_id": archived})
    assert moved.status_code == 422


def test_negative_or_non_numeric_rewards_are_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    entry = knowledge(client, csrf)
    for field, value in (("payout", "-1"), ("bonus", "-0.01"), ("payout", "abc"), ("payout", "NaN"), ("bonus", "inf")):
        _id, response = finding(client, csrf, program_id, entry, **{field: value})
        assert response.status_code == 422, (field, value, response.text)


def test_invalid_finding_status_and_severity_are_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    entry = knowledge(client, csrf)
    for overrides in ({"status": "unknown"}, {"severity": "extreme"}):
        _id, response = finding(client, csrf, program_id, entry, **overrides)
        assert response.status_code == 422, overrides


def test_invalid_and_out_of_order_dates_are_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    entry = knowledge(client, csrf)
    cases = [
        {"submitted_at": "not-a-date"},
        {"discovered_at": "2026-02-01", "submitted_at": "2026-01-01"},
        {"submitted_at": "2026-02-01", "triaged_at": "2026-01-01"},
        {"submitted_at": "2026-02-01", "rewarded_at": "2026-01-01"},
    ]
    for overrides in cases:
        _id, response = finding(client, csrf, program_id, entry, **overrides)
        assert response.status_code == 422, (overrides, response.text)


def test_unsafe_submission_url_is_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    entry = knowledge(client, csrf)
    _id, response = finding(client, csrf, program_id, entry, report_url="javascript:alert(1)")
    assert response.status_code == 422


def test_oversized_upload_leaves_no_file_or_database_row(negative_workspace):
    client, csrf, data_dir = negative_workspace
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "Too large",
            "bug_type": "XSS",
            "default_severity": "high",
            "markdown": "# report",
        },
        files={"uploads": ("large.bin", b"x" * 17, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert list((data_dir / "evidence").iterdir()) == []
    assert "Too large" not in client.get("/knowledge").text


def test_upload_filename_is_sanitized_and_knowledge_delete_cleans_files(negative_workspace):
    client, csrf, data_dir = negative_workspace
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "With file",
            "bug_type": "XSS",
            "default_severity": "high",
            "markdown": "# report",
        },
        files={"uploads": ("../../payload.png", b"1234", "image/png")},
    )
    assert response.status_code == 303
    knowledge_id = response.headers["location"].rsplit("/", 1)[-1]
    evidence_files = list((data_dir / "evidence").iterdir())
    assert len(evidence_files) == 1
    assert evidence_files[0].parent == data_dir / "evidence"
    detail = client.get(f"/knowledge/{knowledge_id}").text
    assert "payload.png" in detail
    assert "../" not in detail
    assert (data_dir / "markdown" / f"{knowledge_id}.md").exists()

    deleted = client.post(f"/knowledge/{knowledge_id}/delete", data={"csrf": csrf})
    assert deleted.status_code == 303
    assert list((data_dir / "evidence").iterdir()) == []
    assert not (data_dir / "markdown" / f"{knowledge_id}.md").exists()
    assert client.get(f"/knowledge/{knowledge_id}").status_code == 404


def test_cvss_and_taxonomy_validation_rejects_bad_values(negative_workspace):
    client, csrf, _ = negative_workspace
    for score in ("-0.1", "10.1", "NaN", "eleven"):
        response = client.post(
            "/knowledge/new",
            data={
                "csrf": csrf,
                "title": f"CVSS {score}",
                "bug_type": "XSS",
                "default_severity": "high",
                "cvss_score": score,
            },
        )
        assert response.status_code == 422, score
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "Bad taxonomy",
            "bug_type": "NOT-A-TYPE",
            "default_severity": "extreme",
        },
    )
    assert response.status_code == 422


def test_invalid_currency_and_program_severity_are_rejected(negative_workspace):
    client, csrf, _ = negative_workspace
    program_id = program(client, csrf)
    entry = knowledge(client, csrf)
    for overrides in ({"payout": "100", "currency": "XYZ"}, {"program_severity": "extreme"}):
        _finding_id, response = finding(client, csrf, program_id, entry, **overrides)
        assert response.status_code == 422, overrides


def test_pure_negative_search_and_date_bounds_do_not_crash(negative_workspace):
    client, csrf, _ = negative_workspace
    knowledge(client, csrf, title="OAuth issue")
    knowledge(client, csrf, title="CSRF issue")
    negative = client.get("/search?q=-csrf")
    assert negative.status_code == 200
    assert "OAuth issue" in negative.text
    assert "CSRF issue" not in negative.text
    bounded = client.get("/search?q=after:2020-01-01+before:2100-01-01")
    assert bounded.status_code == 200
    assert "OAuth issue" in bounded.text


@pytest.mark.parametrize(
    "query",
    [
        '"',
        '"unterminated phrase',
        ":",
        "status:",
        "cvss:NaN",
        "cvss:>=",
        "after:2026-99-99",
        "before:not-a-date",
        "is:unknown",
        "has:unknown",
        "kind:unknown",
        "serverity:high",
        "https://example.com:8443/a:b",
        "((((()))))",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "lỗ hổng 🔥",
        "-csrf",
        '-"exact phrase"',
        "a " * 200,
    ],
)
def test_malformed_search_queries_never_return_500(negative_workspace, query):
    client, _csrf, _ = negative_workspace
    response = client.get("/api/search", params={"q": query})
    assert response.status_code == 200, (query, response.text)
    payload = response.json()
    assert set(payload) == {"query", "groups", "total", "warnings"}


def test_multi_upload_failure_cleans_every_file(negative_workspace):
    client, csrf, data_dir = negative_workspace
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "Atomic upload",
            "bug_type": "XSS",
            "default_severity": "high",
            "markdown": "# report",
        },
        files=[
            ("uploads", ("small.txt", b"ok", "text/plain")),
            ("uploads", ("too-large.bin", b"x" * 17, "application/octet-stream")),
        ],
    )
    assert response.status_code == 413
    assert list((data_dir / "evidence").iterdir()) == []
    assert "Atomic upload" not in client.get("/knowledge").text


def test_server_enforces_title_length_limits(negative_workspace):
    client, csrf, _ = negative_workspace
    assert client.post("/programs/new", data={"csrf": csrf, "name": "P" * 181}).status_code == 422
    assert (
        client.post(
            "/knowledge/new",
            data={
                "csrf": csrf,
                "title": "K" * 241,
                "bug_type": "XSS",
                "default_severity": "high",
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/capture",
            data={
                "csrf": csrf,
                "title": "C" * 241,
                "capture": "GET /",
            },
        ).status_code
        == 422
    )
