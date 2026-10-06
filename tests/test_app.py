import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def csrf(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


@pytest.fixture
def workspace(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        admin_password="mật-khẩu-thử-nghiệm",
        session_secret="test-session-secret-that-is-long-enough",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
    )
    app = create_app(settings)
    with TestClient(app, follow_redirects=False) as client:
        login_page = client.get("/login")
        response = client.post(
            "/login", data={"username": "admin", "password": settings.admin_password, "csrf": csrf(login_page.text)}
        )
        assert response.status_code == 303
        home = client.get("/")
        yield client, csrf(home.text), tmp_path


def create_program(client: TestClient, token: str, name: str) -> str:
    response = client.post(
        "/programs/new",
        data={
            "csrf": token,
            "name": name,
            "platform": "HackerOne",
            "handle": name.casefold(),
            "url": "https://example.com/program",
            "notes": "Phạm vi kiểm thử tiếng Việt",
        },
    )
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


def create_knowledge(client: TestClient, token: str) -> str:
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": token,
            "title": "Chiếm quyền tài khoản qua OAuth",
            "bug_type": "OAuth / SSO",
            "default_severity": "critical",
            "summary": "Sai lệch trạng thái cho phép kẻ tấn công liên kết phiên đăng nhập.",
            "endpoint": "GET /oauth/callback",
            "technology": "OAuth 2.0, FastAPI",
            "cwe": "CWE-384",
            "cvss_score": "9.1",
            "research_notes": "Payload thử nghiệm và bài học điều tra bằng tiếng Việt.",
            "program_id": "",
            "markdown": (
                "# Tóm tắt\n\n## Các bước tái hiện\n\n1. Mở liên kết đăng nhập.\n2. Thay đổi `state`.\n\n"
                "## Impact\n\nAccount takeover."
            ),
            "remediation": "Ràng buộc state với phiên người dùng.",
            "references": "https://datatracker.ietf.org/doc/html/rfc6749",
        },
    )
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


def link_finding(client: TestClient, token: str, program_id: str, knowledge_id: str, target: str):
    response = client.post(
        "/findings/new",
        data={
            "csrf": token,
            "program_id": program_id,
            "knowledge_id": knowledge_id,
            "target": target,
            "scope": "Web application",
            "status": "submitted",
            "severity": "critical",
            "report_id": "H1-123",
            "report_url": "https://example.com/report",
            "submitted_at": "2026-09-15",
            "payout": "",
            "private_notes": "Đang chờ phản hồi từ triage.",
        },
    )
    assert response.status_code == 303


def test_authentication_is_required(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'auth.db'}",
        admin_password="secret",
        session_secret="a-long-test-session-secret-value",
        max_upload_bytes=1024,
        secure_cookies=False,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        assert client.get("/health").status_code == 200
        assert "Sign in" in client.get("/login").text
        response = client.get("/")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_unicode_reusable_knowledge_search_and_markdown(workspace):
    client, token, data_dir = workspace
    program_a = create_program(client, token, "Chương trình Alpha")
    program_b = create_program(client, token, "Chương trình Beta")
    knowledge_id = create_knowledge(client, token)

    link_finding(client, token, program_a, knowledge_id, "api.alpha.vn")
    link_finding(client, token, program_b, knowledge_id, "login.beta.vn")

    page = client.get(f"/knowledge/{knowledge_id}")
    assert page.status_code == 200
    assert "Chiếm quyền tài khoản qua OAuth" in page.text
    assert "Chương trình Alpha" in page.text
    assert "Chương trình Beta" in page.text
    assert "GET /oauth/callback" in page.text
    assert "CWE-384" in page.text
    assert "Payload thử nghiệm" in page.text

    contextual = client.get(f"/knowledge/{knowledge_id}", params={"program_id": program_a})
    assert contextual.status_code == 200
    assert 'id="program-explorer"' in contextual.text
    assert "Chương trình Alpha" in contextual.text

    search = client.get("/knowledge", params={"q": "đăng nhập"})
    assert search.status_code == 200
    assert "Chiếm quyền tài khoản qua OAuth" in search.text
    technology_search = client.get("/knowledge", params={"q": "FastAPI"})
    assert "Chiếm quyền tài khoản qua OAuth" in technology_search.text

    registry = client.get("/findings", params={"status": "submitted"})
    assert registry.status_code == 200
    assert "Chương trình Alpha" in registry.text
    assert "Chương trình Beta" in registry.text
    assert "Clear" in registry.text
    assert "built-in method" not in registry.text

    document = (data_dir / "markdown" / f"{knowledge_id}.md").read_text(encoding="utf-8")
    assert "Các bước tái hiện" in document
    assert "Chương trình Alpha" in document
    assert "Chương trình Beta" in document
    assert "program_uses:" in document
    assert "endpoint: GET /oauth/callback" in document
    assert "technology: OAuth 2.0, FastAPI" in document
    assert "cwe: CWE-384" in document
    assert "cvss_score: 9.1" in document


def test_evidence_upload_view_and_delete(workspace):
    client, token, data_dir = workspace
    knowledge_id = create_knowledge(client, token)
    payload = b"\x89PNG\r\n\x1a\nminimal-test-image"
    response = client.post(
        f"/knowledge/{knowledge_id}/evidence",
        data={"csrf": token},
        files={"upload": ("ảnh-bằng-chứng.png", payload, "image/png")},
    )
    assert response.status_code == 303

    detail = client.get(f"/knowledge/{knowledge_id}")
    assert "ảnh-bằng-chứng.png" in detail.text
    evidence_id = re.search(r"/evidence/([a-f0-9-]+)", detail.text).group(1)
    viewed = client.get(f"/evidence/{evidence_id}")
    assert viewed.status_code == 200
    assert viewed.content == payload
    assert viewed.headers["x-content-type-options"] == "nosniff"

    deleted = client.post(f"/evidence/{evidence_id}/delete", data={"csrf": token})
    assert deleted.status_code == 303
    assert not any((data_dir / "evidence").iterdir())


def test_editor_uploads_evidence_during_creation(workspace):
    client, token, data_dir = workspace
    payload = b"\x89PNG\r\n\x1a\neditor-evidence"
    response = client.post(
        "/knowledge/new",
        data={
            "csrf": token,
            "title": "Editor evidence upload",
            "bug_type": "File Upload",
            "default_severity": "medium",
            "summary": "Evidence is saved with the vulnerability report.",
            "markdown": "# Summary\n\nEvidence attached from the report editor.",
            "remediation": "",
            "references": "",
        },
        files=[("uploads", ("editor-proof.png", payload, "image/png"))],
    )
    assert response.status_code == 303
    detail = client.get(response.headers["location"])
    assert detail.status_code == 200
    assert "editor-proof.png" in detail.text
    stored = list((data_dir / "evidence").iterdir())
    assert len(stored) == 1
    assert stored[0].read_bytes() == payload


def test_legacy_sqlite_schema_is_migrated_in_place(tmp_path: Path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute("""
            CREATE TABLE knowledge_entries (
                id VARCHAR(36) PRIMARY KEY, slug VARCHAR(220), title VARCHAR(240), bug_type VARCHAR(100),
                default_severity VARCHAR(20), tags_json TEXT, summary TEXT, markdown TEXT,
                remediation TEXT, "references" TEXT, created_at DATETIME, updated_at DATETIME
            )
        """)
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{database}",
        admin_password="secret",
        session_secret="legacy-migration-session-secret-value",
        max_upload_bytes=1024,
        secure_cookies=False,
    )
    create_app(settings)
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(knowledge_entries)")}
    assert {"endpoint", "technology", "cwe", "cvss_score", "research_notes", "use_for_ai"} <= columns
    assert not {"tags_json", "related_ids_json"} & columns


def test_program_archive_restore_and_knowledge_copy(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Lifecycle Program")
    archived = client.post(f"/programs/{program_id}/archive", data={"csrf": token})
    assert archived.status_code == 303
    assert "Restore" in client.get(archived.headers["location"]).text
    restored = client.post(f"/programs/{program_id}/restore", data={"csrf": token})
    assert restored.status_code == 303
    assert "Archive" in client.get(restored.headers["location"]).text

    knowledge_id = create_knowledge(client, token)
    copied = client.post(f"/knowledge/{knowledge_id}/copy", data={"csrf": token})
    assert copied.status_code == 303
    edit_page = client.get(copied.headers["location"])
    assert edit_page.status_code == 200
    assert "Chiếm quyền tài khoản qua OAuth (Copy)" in edit_page.text


def test_research_started_from_a_program_is_linked_through_the_finding_form(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Explorer Program")
    response = client.post(
        f"/knowledge/new?program_id={program_id}",
        data={
            "csrf": token,
            "title": "IDOR in account export",
            "bug_type": "Access Control",
            "default_severity": "high",
            "summary": "Authorization is missing on account export.",
            "endpoint": "GET /api/accounts/{id}/export",
            "technology": "REST, Django",
            "cwe": "CWE-639",
            "cvss_score": "8.1",
            "research_notes": "Reusable object-level authorization test pattern.",
            "markdown": "# Summary\n\nMissing object-level authorization.",
            "remediation": "Authorize the requested account against the session.",
            "references": "https://owasp.org/API-Security/",
        },
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/findings/new?") and f"program_id={program_id}" in location
    knowledge_id = location.split("knowledge_id=", 1)[1].split("&", 1)[0]
    linked = client.post(
        "/findings/new",
        data={
            "csrf": token,
            "program_id": program_id,
            "knowledge_id": knowledge_id,
            "target": "api.explorer.example",
            "scope": "Account export API",
            "status": "ready_to_submit",
            "severity": "high",
            "report_id": "DRAFT-17",
            "discovered_at": "2026-09-16",
            "private_notes": "Retest with a second account.",
        },
    )
    assert linked.status_code == 303
    detail = client.get(linked.headers["location"])
    assert detail.status_code == 200
    assert 'id="program-explorer"' in detail.text
    assert "IDOR in account export" in detail.text
    filtered = client.get("/findings", params={"status": "ready_to_submit", "program_id": program_id})
    assert "api.explorer.example" in filtered.text


def create_knowledge_custom(client: TestClient, token: str, **overrides) -> str:
    data = {
        "csrf": token,
        "title": "Base entry",
        "bug_type": "XSS",
        "default_severity": "medium",
        "summary": "",
        "endpoint": "",
        "technology": "",
        "cwe": "",
        "cvss_score": "",
        "research_notes": "",
        "program_id": "",
        "markdown": "# Summary\n",
        "remediation": "",
        "references": "",
    }
    data.update(overrides)
    response = client.post("/knowledge/new", data=data)
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1].split("?")[0]


def candidate_ids(client: TestClient, token: str, **fields) -> list[str]:
    payload = {"csrf": token}
    payload.update(fields)
    response = client.post("/knowledge/candidates", data=payload)
    assert response.status_code == 200
    return [item["id"] for item in response.json()["candidates"]]


def test_candidate_relations_from_shared_signals(workspace):
    client, token, _data_dir = workspace
    shared_cwe = create_knowledge_custom(
        client,
        token,
        title="Reflected XSS in search",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    shared_tech = create_knowledge_custom(
        client,
        token,
        title="Stored XSS in comments",
        bug_type="XSS",
        cwe="CWE-116",
        technology="React, Node",
    )
    unrelated = create_knowledge_custom(
        client,
        token,
        title="Broken crypto in token",
        bug_type="Cryptography",
        cwe="CWE-327",
        technology="Java",
    )

    ids = candidate_ids(
        client,
        token,
        current_id="",
        cwe="CWE-79",
        bug_type="XSS",
        technology="React",
        title="DOM XSS in profile",
        summary="Client-side sink.",
    )
    assert shared_cwe in ids
    assert shared_tech in ids
    assert unrelated not in ids


def test_candidate_excludes_current_entry(workspace):
    client, token, _data_dir = workspace
    entry_id = create_knowledge_custom(
        client,
        token,
        title="Self entry",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    ids = candidate_ids(
        client,
        token,
        current_id=entry_id,
        cwe="CWE-79",
        bug_type="XSS",
        technology="React",
        title="Self entry",
    )
    assert entry_id not in ids


def test_accepted_candidate_persists_to_related_ids_and_markdown(workspace):
    client, token, data_dir = workspace
    target = create_knowledge_custom(
        client,
        token,
        title="OAuth state confusion",
        bug_type="OAuth / SSO",
        cwe="CWE-384",
    )
    # Accepting a suggestion selects it in the related_ids <select>, which the form posts.
    source = create_knowledge_custom(
        client,
        token,
        title="OAuth redirect abuse",
        bug_type="OAuth / SSO",
        cwe="CWE-601",
        related_ids=[target],
    )
    detail = client.get(f"/knowledge/{source}")
    assert "OAuth state confusion" in detail.text
    document = (data_dir / "markdown" / f"{source}.md").read_text(encoding="utf-8")
    assert "related_vulnerabilities:" in document
    assert target in document


def test_candidate_form_renders_relate_chips_region(workspace):
    client, token, _data_dir = workspace
    create_knowledge_custom(client, token, title="Existing entry", cwe="CWE-79")
    page = client.get("/knowledge/new")
    assert page.status_code == 200
    assert "data-relate" in page.text
    assert "data-relate-chips" in page.text
    # The plain multi-select remains as a fallback.
    assert 'name="related_ids"' in page.text
    assert "Suggested relations" in page.text


def test_backlink_view_reveals_incoming_edges(workspace):
    client, token, _data_dir = workspace
    target = create_knowledge_custom(client, token, title="Target entry B", cwe="CWE-79")
    detail_before = client.get(f"/knowledge/{target}")
    assert detail_before.status_code == 200
    assert "Source entry A" not in detail_before.text

    source = create_knowledge_custom(
        client,
        token,
        title="Source entry A",
        cwe="CWE-89",
        related_ids=[target],
    )
    # B never stored the link; its page derives it from A.
    detail_after = client.get(f"/knowledge/{target}")
    assert detail_after.status_code == 200
    assert "Referenced by" in detail_after.text
    assert "Source entry A" in detail_after.text
    assert f"/knowledge/{source}" in detail_after.text


def test_backlink_excludes_mutual_links_kept_under_related(workspace):
    client, token, _data_dir = workspace
    first = create_knowledge_custom(client, token, title="Mutual A", cwe="CWE-79")
    second = create_knowledge_custom(client, token, title="Mutual B", cwe="CWE-89", related_ids=[first])
    response = client.post(
        f"/knowledge/{first}/edit",
        data={
            "csrf": token,
            "title": "Mutual A",
            "bug_type": "XSS",
            "default_severity": "medium",
            "summary": "",
            "endpoint": "",
            "technology": "",
            "cwe": "CWE-79",
            "cvss_score": "",
            "research_notes": "",
            "program_id": "",
            "markdown": "# Summary\n",
            "remediation": "",
            "references": "",
            "related_ids": second,
        },
    )
    assert response.status_code == 303
    detail = client.get(f"/knowledge/{first}")
    assert detail.status_code == 200
    # A mutual link is listed once, under Related, and not again under Referenced by.
    assert detail.text.count("Mutual B") == 1


def test_backlink_materialized_in_markdown_frontmatter(workspace):
    client, token, data_dir = workspace
    target = create_knowledge_custom(client, token, title="Provenance target", cwe="CWE-79")
    source = create_knowledge_custom(
        client,
        token,
        title="Provenance source",
        cwe="CWE-89",
        related_ids=[target],
    )
    document = (data_dir / "markdown" / f"{target}.md").read_text(encoding="utf-8")
    assert "referenced_by:" in document
    assert source in document


def test_copy_creates_backlink_on_source(workspace):
    client, token, data_dir = workspace
    knowledge_id = create_knowledge_custom(client, token, title="Copy source", cwe="CWE-79")
    copied = client.post(f"/knowledge/{knowledge_id}/copy", data={"csrf": token})
    assert copied.status_code == 303
    copy_id = copied.headers["location"].rsplit("/", 2)[-2]
    # A copy links to its source, so the source lists it under Referenced by.
    detail = client.get(f"/knowledge/{knowledge_id}")
    assert detail.status_code == 200
    assert "Referenced by" in detail.text
    assert "Copy source (Copy)" in detail.text
    document = (data_dir / "markdown" / f"{knowledge_id}.md").read_text(encoding="utf-8")
    assert "referenced_by:" in document
    assert copy_id in document


def test_rediscover_panel_surfaces_related_research_on_knowledge_view(workspace):
    client, token, _data_dir = workspace
    prior = create_knowledge_custom(
        client,
        token,
        title="Prior reflected XSS",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    current = create_knowledge_custom(
        client,
        token,
        title="New DOM XSS",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    detail = client.get(f"/knowledge/{current}")
    assert detail.status_code == 200
    assert "Related research" in detail.text
    assert "Prior reflected XSS" in detail.text
    assert f"/knowledge/{prior}" in detail.text
    assert "Same CWE" in detail.text


def test_rediscover_excludes_entries_already_related_or_backlinked(workspace):
    client, token, _data_dir = workspace
    already = create_knowledge_custom(
        client,
        token,
        title="Already linked XSS",
        bug_type="XSS",
        cwe="CWE-79",
    )
    current = create_knowledge_custom(
        client,
        token,
        title="Current XSS",
        bug_type="XSS",
        cwe="CWE-79",
        related_ids=[already],
    )
    detail = client.get(f"/knowledge/{current}")
    assert detail.status_code == 200
    # Listed under Related only, not suggested again under Related research.
    assert detail.text.count("Already linked XSS") == 1


def test_rediscover_absent_when_no_related_research(workspace):
    client, token, _data_dir = workspace
    lonely = create_knowledge_custom(
        client,
        token,
        title="Only entry",
        bug_type="Cryptography",
        cwe="CWE-327",
    )
    detail = client.get(f"/knowledge/{lonely}")
    assert detail.status_code == 200
    assert "Related research" not in detail.text


def test_rediscover_panel_on_program_scope_aggregates_findings(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Rediscover Program")
    linked = create_knowledge_custom(
        client,
        token,
        title="Linked program XSS",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    link_finding(client, token, program_id, linked, "app.rediscover.example")
    related = create_knowledge_custom(
        client,
        token,
        title="Unlinked prior XSS",
        bug_type="XSS",
        cwe="CWE-79",
        technology="React",
    )
    detail = client.get(f"/programs/{program_id}")
    assert detail.status_code == 200
    assert "Related research" in detail.text
    assert "Unlinked prior XSS" in detail.text
    assert f"/knowledge/{related}" in detail.text
    panel = re.search(r'class="related-list rediscover-list">(.*?)</div>', detail.text, re.S)
    assert panel, "rediscovery panel missing"
    assert "Unlinked prior XSS" in panel.group(1)
    # Research already linked to the program is not suggested again.
    assert "Linked program XSS" not in panel.group(1)


def test_rediscover_absent_on_program_with_no_findings(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Empty Program")
    detail = client.get(f"/programs/{program_id}")
    assert detail.status_code == 200
    assert "Related research" not in detail.text


def test_environment_settings_fail_closed_on_insecure_secrets(monkeypatch):
    monkeypatch.delenv("VULNS_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("VULNS_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="VULNS_ADMIN_PASSWORD"):
        Settings.from_env()
    monkeypatch.setenv("VULNS_ADMIN_PASSWORD", "secure-password")
    monkeypatch.setenv("VULNS_SESSION_SECRET", "short")
    with pytest.raises(RuntimeError, match="VULNS_SESSION_SECRET"):
        Settings.from_env()


def test_session_secret_is_generated_once_and_reused(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VULNS_ADMIN_PASSWORD", "secure-password")
    monkeypatch.delenv("VULNS_SESSION_SECRET", raising=False)
    first = Settings.from_env().session_secret
    assert len(first) >= 32
    assert (tmp_path / ".session-secret").read_text(encoding="utf-8") == first
    assert Settings.from_env().session_secret == first


def test_unsafe_external_urls_are_rejected(workspace):
    client, token, _data_dir = workspace
    response = client.post(
        "/programs/new",
        data={
            "csrf": token,
            "name": "Unsafe URL Program",
            "platform": "Independent",
            "url": "javascript:alert(1)",
            "handle": "unsafe",
            "notes": "",
        },
    )
    assert response.status_code == 422


def test_security_headers_are_applied(workspace):
    client, _token, _data_dir = workspace
    response = client.get("/")
    assert response.status_code == 200
    assert "object-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_every_taxonomy_value_has_an_operator_label():
    """Every status and severity has a display label."""
    from app.i18n import TERMS
    from app.taxonomy import SEVERITIES, STATUSES

    expected = set(SEVERITIES) | set(STATUSES)
    missing = expected - set(TERMS)
    assert not missing, f"missing taxonomy labels: {sorted(missing)}"


def test_term_leaves_display_ready_values_untouched():
    """Already-cased bug types such as "OAuth / SSO" are left untouched."""
    from app.i18n import term

    assert term("OAuth / SSO") == "OAuth / SSO"
    assert term("SSRF") == "SSRF"
    assert term("brand_new_status") == "Brand new status"
    assert term(None) == ""


# Lookup


def make_entry(client: TestClient, token: str, **overrides) -> str:
    """Create a knowledge entry with defaults so a test only states what matters."""
    data = {
        "csrf": token,
        "title": "Untitled research",
        "bug_type": "XSS",
        "default_severity": "medium",
        "summary": "",
        "endpoint": "",
        "technology": "",
        "cwe": "",
        "cvss_score": "",
        "research_notes": "",
        "program_id": "",
        "markdown": "## Summary\n\nBody.",
        "remediation": "",
        "references": "",
    }
    data.update(overrides)
    response = client.post("/knowledge/new", data=data)
    assert response.status_code == 303, response.text[:400]
    return response.headers["location"].rsplit("/", 1)[-1]


def test_query_parser_understands_fields_phrases_and_negation():
    from app.search import parse_query

    parsed = parse_query('"open redirect" oauth sev:critical -csrf -status:draft cvss:>=8.5 kind:knowledge')
    assert parsed.phrases == ["open redirect"]
    assert parsed.words == ["oauth"]
    assert parsed.excluded_words == ["csrf"]
    assert parsed.values("severity") == ["critical"]
    assert parsed.values("status", negated=True) == ["draft"]
    assert parsed.comparisons["cvss"][0].op == ">="
    assert parsed.comparisons["cvss"][0].value == 8.5
    assert parsed.kinds == ("knowledge",)
    assert parsed.warnings == []
    expression = parsed.fts_expression()
    assert '"open redirect"' in expression and "NOT" in expression


def test_query_parser_accepts_field_aliases_and_normalises_cwe():
    from app.search import parse_query

    assert parse_query("severity:high").values("severity") == ["high"]
    assert parse_query("sev:high").values("severity") == ["high"]
    assert parse_query("bug:xss").values("bug_type") == ["xss"]
    assert parse_query("class:xss").values("bug_type") == ["xss"]
    # 352, cwe-352 and CWE352 all describe the same weakness.
    for spelling in ("cwe:352", "cwe:CWE-352", "cwe:cwe352"):
        assert parse_query(spelling).values("cwe") == ["352"]


def test_unknown_field_is_warned_but_still_searched_as_text():
    """A misspelled field is reported instead of silently filtering."""
    from app.search import parse_query

    parsed = parse_query("serverity:high")
    assert parsed.warnings == ["serverity"]
    assert parsed.words == ["serverity:high"]


def test_url_with_colon_is_not_mistaken_for_a_filter():
    from app.search import parse_query

    parsed = parse_query("https://acme.example.com/oauth")
    assert parsed.warnings == []
    assert parsed.words == ["https://acme.example.com/oauth"]


def test_lookup_finds_knowledge_findings_and_programs_in_one_query(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Acme Cloud")
    knowledge_id = create_knowledge(client, token)
    link_finding(client, token, program_id, knowledge_id, "auth.acme.example.com")

    page = client.get("/search?q=acme").text
    assert "Acme Cloud" in page
    # Matched via the link: the highlighter splits matched words with <mark>.
    assert f"program_id={program_id}" in page
    assert "H1-123" in page


def test_lookup_field_filter_narrows_results(workspace):
    client, token, _data_dir = workspace
    make_entry(client, token, title="Critical injection chain", default_severity="critical")
    make_entry(client, token, title="Cosmetic low issue", default_severity="low")

    critical_only = client.get("/search?q=sev:critical").text
    assert "Critical injection chain" in critical_only
    assert "Cosmetic low issue" not in critical_only


def test_lookup_negation_excludes_matches(workspace):
    client, token, _data_dir = workspace
    make_entry(client, token, title="SSRF via webhook")
    make_entry(client, token, title="SSRF via image parser")

    page = client.get("/search?q=ssrf+-webhook").text
    assert "SSRF via image parser" in page
    assert "SSRF via webhook" not in page


def test_lookup_numeric_threshold_filters_on_cvss(workspace):
    client, token, _data_dir = workspace
    make_entry(client, token, title="Severe deserialisation", cvss_score="9.4")
    make_entry(client, token, title="Minor disclosure", cvss_score="3.1")

    page = client.get("/search?q=cvss:>=8").text
    assert "Severe deserialisation" in page
    assert "Minor disclosure" not in page


def test_lookup_is_orphan_finds_research_with_no_program(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Globex")
    linked = make_entry(client, token, title="Linked research")
    make_entry(client, token, title="Unlinked research")
    link_finding(client, token, program_id, linked, "app.globex.example.com")

    page = client.get("/search?q=is:orphan+kind:knowledge").text
    assert "Unlinked research" in page
    assert "Linked research" not in page


def test_lookup_ranks_title_matches_above_body_only_matches(workspace):
    """Results keep relevance order rather than recency."""
    client, token, _data_dir = workspace
    make_entry(client, token, title="Unrelated topic", markdown="Mentions xslt once in passing.")
    make_entry(client, token, title="XSLT injection in the report renderer", markdown="## Summary\n\nXSLT.")

    page = client.get("/search?q=xslt&kind=knowledge").text
    assert page.index("XSLT injection in the report renderer") < page.index("Unrelated topic")


def test_lookup_is_diacritic_insensitive_for_vietnamese(workspace):
    client, token, _data_dir = workspace
    make_entry(client, token, title="Lỗ hổng chiếm quyền điều khiển")

    # Typed without diacritics.
    page = client.get("/search?q=lo+hong").text
    assert "Lỗ hổng chiếm quyền điều khiển" in page


def test_program_index_is_maintained_by_triggers(workspace):
    """Programs and findings are indexed by SQL triggers, so edits from any route stay searchable."""
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Initech Portal")
    assert "Initech Portal" in client.get("/search?q=initech").text

    edit = client.post(
        f"/programs/{program_id}/edit",
        data={
            "csrf": token,
            "name": "Umbrella Portal",
            "platform": "Bugcrowd",
            "handle": "umbrella",
            "url": "",
            "notes": "Renamed program",
        },
    )
    assert edit.status_code == 303
    # The old name must stop matching and the new one must start.
    assert "Initech" not in client.get("/search?q=initech").text
    assert "Umbrella Portal" in client.get("/search?q=umbrella").text

    delete = client.post(f"/programs/{program_id}/delete", data={"csrf": token})
    assert delete.status_code == 303
    assert "Umbrella Portal" not in client.get("/search?q=umbrella").text


def test_search_api_returns_grouped_json(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Acme Cloud")
    knowledge_id = create_knowledge(client, token)
    link_finding(client, token, program_id, knowledge_id, "auth.acme.example.com")

    payload = client.get("/api/search?q=oauth").json()
    assert payload["total"] >= 1
    kinds = {group["kind"] for group in payload["groups"]}
    assert "knowledge" in kinds
    for group in payload["groups"]:
        for item in group["items"]:
            assert item["url"].startswith("/")
            # The palette inserts these as text nodes, so no markup may leak in.
            assert "<mark>" not in item["snippet"]


def test_search_snippet_escapes_stored_payloads(workspace):
    """Snippets are HTML-escaped; only the highlighter adds <mark>."""
    client, token, _data_dir = workspace
    make_entry(
        client,
        token,
        title="Reflected XSS proof of concept",
        markdown='## PoC\n\n<script>alert("pwned")</script> uniquepayloadtoken\n',
    )

    page = client.get("/search?q=uniquepayloadtoken").text
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    # The highlight itself is still rendered as real markup.
    assert "<mark>uniquepayloadtoken</mark>" in page


def test_highlight_never_emits_unescaped_markup():
    from app.database import HIGHLIGHT_CLOSE, HIGHLIGHT_OPEN
    from app.search import highlight

    raw = f"<img src=x onerror=alert(1)> {HIGHLIGHT_OPEN}needle{HIGHLIGHT_CLOSE}"
    rendered = str(highlight(raw))
    assert "<img" not in rendered
    assert "&lt;img" in rendered
    assert "<mark>needle</mark>" in rendered


def test_registry_search_box_accepts_the_query_language(workspace):
    """Registry search boxes accept the query language."""
    client, token, _data_dir = workspace
    make_entry(client, token, title="Critical SSRF chain", default_severity="critical")
    make_entry(client, token, title="Low severity typo", default_severity="low")

    page = client.get("/knowledge?q=ssrf+sev:critical").text
    assert "Critical SSRF chain" in page
    assert "Low severity typo" not in page


# Bounty tracking


def link_bounty_finding(client: TestClient, token: str, program_id: str, knowledge_id: str, **overrides) -> str:
    data = {
        "csrf": token,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "target": "api.example.com",
        "scope": "Web",
        "status": "paid",
        "severity": "high",
        "report_id": "H1-900",
        "report_url": "",
        "discovered_at": "2026-01-01",
        "submitted_at": "2026-01-05",
        "triaged_at": "2026-01-08",
        "resolved_at": "2026-01-20",
        "rewarded_at": "2026-01-25",
        "payout": "800",
        "bonus": "200",
        "currency": "USD",
        "program_severity": "",
        "duplicate_of": "",
        "private_notes": "",
    }
    data.update(overrides)
    response = client.post("/findings/new", data=data)
    assert response.status_code == 303, response.text[:400]
    return response.headers["location"]


def test_bounty_fields_round_trip_through_the_finding_form(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Bounty Co")
    knowledge_id = create_knowledge(client, token)
    location = link_bounty_finding(
        client, token, program_id, knowledge_id, program_severity="medium", duplicate_of="H1-555"
    )
    finding_id = location.split("finding_id=")[-1]

    # Re-open the edit form: every value must come back as it was submitted.
    form = client.get(f"/findings/{finding_id}/edit").text
    assert 'name="triaged_at" value="2026-01-08"' in form
    assert 'name="rewarded_at" value="2026-01-25"' in form
    assert 'name="resolved_at" value="2026-01-20"' in form
    assert 'name="payout" value="800' in form
    assert 'name="bonus" value="200' in form
    assert 'name="duplicate_of" value="H1-555"' in form
    assert '<option value="USD" selected>USD</option>' in form
    assert '<option value="medium" selected>' in form


def test_total_reward_and_response_gaps_are_derived(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Gap Co")
    knowledge_id = create_knowledge(client, token)
    link_bounty_finding(client, token, program_id, knowledge_id)

    page = client.get(f"/programs/{program_id}").text
    # 800 payout + 200 bonus, and 2026-01-05 -> 01-08 -> 01-25 is 3 then 20 days.
    assert "1000" in page
    assert ">3<" in page
    assert ">20<" in page


def test_day_gap_is_defensive_about_bad_dates():
    from app.models import Finding as FindingModel

    finding = FindingModel(submitted_at="", triaged_at="2026-01-08")
    assert finding.days_to_triage is None
    finding = FindingModel(submitted_at="not-a-date", triaged_at="2026-01-08")
    assert finding.days_to_triage is None
    # A triage date before submission yields no duration.
    finding = FindingModel(submitted_at="2026-02-01", triaged_at="2026-01-08")
    assert finding.days_to_triage is None
    finding = FindingModel(submitted_at="2026-01-05", triaged_at="2026-01-08")
    assert finding.days_to_triage == 3


def test_program_severity_records_a_downgrade():
    from app.models import Finding as FindingModel

    same = FindingModel(severity="high", program_severity="")
    assert same.severity_delta == 0
    assert same.effective_severity == "high"

    down = FindingModel(severity="critical", program_severity="medium")
    assert down.severity_delta < 0
    assert down.effective_severity == "medium"

    up = FindingModel(severity="low", program_severity="high")
    assert up.severity_delta > 0

    # An unrecognised value must not raise on a record page.
    weird = FindingModel(severity="high", program_severity="spicy")
    assert weird.severity_delta == 0


def test_rewards_are_never_summed_across_currencies(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Multi Currency")
    first = create_knowledge(client, token)
    second = make_entry(client, token, title="Second technique")
    link_bounty_finding(client, token, program_id, first, payout="500", bonus="", currency="USD")
    link_bounty_finding(client, token, program_id, second, payout="1000000", bonus="", currency="VND")

    from app.stats import rewards_by_currency

    class Fake:
        def __init__(self, total, currency):
            self._total, self.currency = total, currency

        @property
        def total_reward(self):
            return self._total

    totals = dict(rewards_by_currency([Fake(500, "USD"), Fake(1000000, "VND"), Fake(250, "USD")]))
    assert totals == {"USD": 750.0, "VND": 1000000.0}

    page = client.get(f"/programs/{program_id}").text
    assert "USD" in page and "VND" in page


def test_median_response_metrics_use_the_median_not_the_mean():
    from app.stats import response_metrics

    class Fake:
        def __init__(self, triage, reward):
            self.days_to_triage, self.days_to_reward = triage, reward
            self.total_reward, self.severity_delta = None, 0

    # One outlier must not drag the typical wait: mean would be 105, median is 3.
    metrics = response_metrics([Fake(2, None), Fake(3, None), Fake(310, None)])
    assert metrics["median_triage_days"] == 3
    assert metrics["median_reward_days"] is None
    assert response_metrics([])["median_triage_days"] is None


def test_lookup_filters_on_currency_and_reward_total(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Reward Co")
    rich = make_entry(client, token, title="Well paid chain")
    poor = make_entry(client, token, title="Token gesture")
    # 400 + 300 clears a >500 threshold only when the bonus is counted too.
    link_bounty_finding(client, token, program_id, rich, payout="400", bonus="300", currency="USD")
    link_bounty_finding(client, token, program_id, poor, payout="50", bonus="", currency="EUR")

    high = client.get("/search?q=payout:>500+kind:knowledge").text
    assert "Well paid chain" in high
    assert "Token gesture" not in high

    euros = client.get("/search?q=currency:EUR+kind:knowledge").text
    assert "Token gesture" in euros
    assert "Well paid chain" not in euros


def test_lookup_finds_downgraded_reports(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Strict Triage")
    downgraded = make_entry(client, token, title="Rated down by program")
    agreed = make_entry(client, token, title="Rating accepted")
    link_bounty_finding(client, token, program_id, downgraded, severity="critical", program_severity="low")
    link_bounty_finding(client, token, program_id, agreed, severity="high", program_severity="")

    page = client.get("/search?q=is:downgraded+kind:knowledge").text
    assert "Rated down by program" in page
    assert "Rating accepted" not in page


def test_unrewarded_accepted_filter_accounts_for_bonus_only_awards(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Bonus Only")
    bonus_only = make_entry(client, token, title="Paid as a bonus")
    nothing = make_entry(client, token, title="Accepted but unpaid")
    link_bounty_finding(client, token, program_id, bonus_only, status="accepted", payout="", bonus="150")
    link_bounty_finding(client, token, program_id, nothing, status="accepted", payout="", bonus="")

    page = client.get("/search?q=status:accepted+-has:reward+kind:knowledge").text
    assert "Accepted but unpaid" in page
    # A bonus-only award still counts as rewarded.
    assert "Paid as a bonus" not in page


def test_bounty_facts_are_exported_to_portable_markdown(workspace):
    client, token, data_dir = workspace
    program_id = create_program(client, token, "Export Co")
    knowledge_id = create_knowledge(client, token)
    link_bounty_finding(client, token, program_id, knowledge_id)

    document = (data_dir / "markdown" / f"{knowledge_id}.md").read_text(encoding="utf-8")
    assert "currency: USD" in document
    assert "total_reward: 1000" in document
    assert "rewarded_at: '2026-01-25'" in document or "rewarded_at: 2026-01-25" in document


def test_existing_database_gains_the_bounty_columns(tmp_path: Path):
    """Older databases gain the bounty columns with existing rows intact."""
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE programs (
            id VARCHAR(36) PRIMARY KEY, name VARCHAR(180), platform VARCHAR(80),
            url VARCHAR(500), handle VARCHAR(180), notes TEXT, archived BOOLEAN,
            created_at DATETIME, updated_at DATETIME
        );
        CREATE TABLE knowledge_entries (
            id VARCHAR(36) PRIMARY KEY, slug VARCHAR(220), title VARCHAR(240),
            bug_type VARCHAR(100), default_severity VARCHAR(20), tags_json TEXT,
            summary TEXT, markdown TEXT, remediation TEXT, "references" TEXT,
            created_at DATETIME, updated_at DATETIME
        );
        CREATE TABLE findings (
            id VARCHAR(36) PRIMARY KEY, program_id VARCHAR(36), knowledge_id VARCHAR(36),
            target VARCHAR(500), scope VARCHAR(500), status VARCHAR(30), severity VARCHAR(20),
            report_id VARCHAR(160), report_url VARCHAR(500), submitted_at VARCHAR(30),
            payout FLOAT, private_notes TEXT, created_at DATETIME, updated_at DATETIME
        );
        INSERT INTO findings (id, program_id, knowledge_id, target, status, severity, payout)
        VALUES ('legacy-finding', 'p1', 'k1', 'legacy.example.com', 'paid', 'high', 250.0);
        """
    )
    connection.commit()
    connection.close()

    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{database}",
        admin_password="secret",
        session_secret="a-long-test-session-secret-value",
        max_upload_bytes=1024,
        secure_cookies=False,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        assert client.get("/health").status_code == 200

    verify = sqlite3.connect(database)
    columns = {row[1] for row in verify.execute("PRAGMA table_info(findings)")}
    verify_row = verify.execute(
        "SELECT payout, bonus, currency, triaged_at, program_severity FROM findings WHERE id='legacy-finding'"
    ).fetchone()
    verify.close()

    for column in ("bonus", "currency", "triaged_at", "resolved_at", "rewarded_at", "program_severity", "duplicate_of"):
        assert column in columns, f"{column} was not migrated in"
    # The pre-existing payout survives and the new columns hold their defaults.
    assert verify_row[0] == 250.0
    assert verify_row[1] is None
    assert verify_row[2] == "USD"
    assert verify_row[3] == ""
    assert verify_row[4] == ""


def test_a_filter_a_kind_cannot_express_excludes_that_kind(workspace):
    """A kind that cannot evaluate a filter is excluded, e.g. programs for `currency:USD`."""
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Unrelated Program")
    knowledge_id = create_knowledge(client, token)
    link_bounty_finding(client, token, program_id, knowledge_id, payout="1500", bonus="250")

    payload = client.get("/api/search?q=currency:USD").json()
    kinds = {group["kind"] for group in payload["groups"]}
    assert "program" not in kinds, "programs have no currency, so they must be excluded"
    assert "knowledge" in kinds

    # Same for a numeric bounty threshold and the reward predicates.
    for query in ("payout:>1000", "is:rewarded", "has:bonus"):
        groups = client.get(f"/api/search?q={query}").json()["groups"]
        assert "program" not in {group["kind"] for group in groups}, query

    # A filter every kind understands still searches every kind.
    everything = client.get("/api/search?q=program:Unrelated").json()
    assert "program" in {group["kind"] for group in everything["groups"]}


def test_kind_capability_gate_is_declarative():
    from app.search import kind_can_answer, parse_query

    assert kind_can_answer(parse_query("currency:USD"), "knowledge") is True
    assert kind_can_answer(parse_query("currency:USD"), "finding") is True
    assert kind_can_answer(parse_query("currency:USD"), "program") is False
    assert kind_can_answer(parse_query("is:archived"), "program") is True
    assert kind_can_answer(parse_query("has:poc"), "finding") is False
    assert kind_can_answer(parse_query("cvss:>8"), "program") is False
    # Free text alone is answerable by every kind.
    assert kind_can_answer(parse_query("oauth"), "program") is True


def test_no_template_references_a_missing_translation_key():
    """Every `tr.key` used by a template exists."""
    import re
    from pathlib import Path as _Path

    from app.i18n import TRANSLATIONS

    known = set(TRANSLATIONS)
    # Names provided by the template context rather than the translation table.
    context_names = {"copy", "clear", "continue"}
    missing: dict[str, set[str]] = {}
    for template in _Path("app/templates").glob("*.html"):
        body = template.read_text(encoding="utf-8")
        for key in set(re.findall(r"\btr\.([a-z0-9_]+)", body)):
            if key not in known and key not in context_names:
                missing.setdefault(template.name, set()).add(key)
    assert not missing, f"templates reference unknown translation keys: {missing}"


def test_dashboard_lists_work_waiting_on_the_operator(workspace):
    """The dashboard surfaces what is waiting on the operator."""
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Queue Co")
    knowledge_id = create_knowledge(client, token)
    # A submitted report with no triage date is something the program owes a reply on.
    link_finding(client, token, program_id, knowledge_id, "api.queue.example.com")

    page = client.get("/").text
    assert "Needs attention" in page
    assert "Awaiting reply" in page
    assert "1 item" in page
    assert "1 items" not in page
    assert page.count("Chiếm quyền tài khoản qua OAuth") == 1
    queue_row = page.split('class="queue-row"', 1)[1].split("</a>", 1)[0]
    assert queue_row.index('class="queue-main"') < queue_row.index('class="severity')
    assert 'class="bar-row status-submitted"' in page
    assert "Accepted or later" in page
    expected_metrics = {
        "programs": 1,
        "knowledge": 1,
        "vulnerabilities": 1,
        "open": 1,
        "accepted": 0,
        "rewarded": 0,
    }
    for metric, value in expected_metrics.items():
        assert re.search(
            rf'data-dashboard-metric="{metric}"[^>]*>.*?<strong>{value}</strong>',
            page,
            re.DOTALL,
        )
    # A quick-capture draft is triage work and belongs in the same queue.
    client.post("/capture", data={"csrf": token, "title": "Loose end", "tag": "cache", "capture": "GET /x"})
    queued = client.get("/").text
    assert "Loose end" in queued


def test_new_workspace_dashboard_offers_one_way_forward(workspace):
    """An empty workspace shows a getting-started panel instead of zeros."""
    client, _token, _data_dir = workspace
    page = client.get("/").text
    assert 'class="panel onboarding"' in page
    assert 'href="/knowledge/new"' in page
    assert 'href="/programs/new"' in page
    assert 'href="/knowledge/import"' in page
    assert "data-dashboard-metric" not in page
    assert "Nothing is waiting on you." not in page


def test_dashboard_attention_counts_are_not_capped_by_the_visible_rows(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Backlog Co")
    for index in range(8):
        knowledge_id = make_entry(client, token, title=f"Backlog report {index}")
        link_finding(client, token, program_id, knowledge_id, f"api{index}.backlog.example.com")
    page = client.get("/").text
    queue = page.split('class="panel queue-panel"', 1)[1].split("</section>", 1)[0]
    assert "8 items" in queue
    assert queue.count('class="queue-row"') == 6
    assert re.search(r'<div class="queue-group">\s*<span>Awaiting reply</span>\s*<b>8</b>', queue)
    assert "View all" in queue
    # The group heading carries the status, so rows do not repeat a pill each.
    assert 'class="status ' not in queue


def test_accepted_unpaid_age_counts_from_triage_not_triage_duration():
    from datetime import date, timedelta

    from app.models import Finding

    triaged = (date.today() - timedelta(days=12)).isoformat()
    finding = Finding(status="accepted", submitted_at="2026-01-01", triaged_at=triaged)
    assert finding.days_awaiting_reward == 12
    finding.payout = 100.0
    assert finding.days_awaiting_reward is None
    assert Finding(status="accepted").days_awaiting_reward is None


def test_dashboard_reports_nothing_waiting_when_the_queue_is_clear(workspace):
    client, token, _data_dir = workspace
    create_knowledge(client, token)
    page = client.get("/").text
    assert "Nothing is waiting on you." in page
    assert "Response times appear once submission and triage dates are recorded." in page
    assert "Median days to triage" not in page
    assert "Median days to bounty" not in page


def test_record_drawer_renders_markdown_and_reuses_the_real_editor(workspace):
    client, token, _data_dir = workspace
    knowledge_id = make_entry(
        client,
        token,
        title="Drawer render check",
        markdown="# Drawer heading\n\nRendered body.",
    )

    panel = client.get(f"/knowledge/{knowledge_id}/panel")
    assert panel.status_code == 200
    assert "<h1>Drawer heading</h1>" in panel.text
    assert "&lt;h1&gt;Drawer heading" not in panel.text
    assert f"/knowledge/{knowledge_id}/edit?embed=1" in panel.text

    editor = client.get(f"/knowledge/{knowledge_id}/edit?embed=1")
    assert editor.status_code == 200
    assert 'class="embed-body"' in editor.text
    assert 'class="sidebar"' not in editor.text
    assert 'name="markdown"' in editor.text


def test_registry_tables_have_no_redundant_edit_column(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Drawer Program")
    knowledge_id = create_knowledge(client, token)
    link_finding(client, token, program_id, knowledge_id, "app.drawer.example.com")

    for path in ("/knowledge", "/findings", f"/programs/{program_id}", "/"):
        page = client.get(path).text
        assert 'class="row-action"' not in page, path
        # Vulnerability rows carry their preview endpoint instead.
        if "knowledge" in path or "findings" in path:
            assert "data-record-panel" in page, path


def test_dashboard_does_not_duplicate_global_create_actions(workspace):
    client, _token, _data_dir = workspace
    page = client.get("/").text
    # Create actions live in the top bar; the dashboard toolbar must not repeat them.
    toolbar = page.split('<div class="toolbar">', 1)[1].split('<div class="workspace">', 1)[0]
    assert 'class="toolbar-actions"' not in toolbar
    assert 'href="/capture"' not in toolbar
    assert 'href="/knowledge/new"' not in toolbar


def test_record_view_does_not_repeat_the_summary_above_markdown(workspace):
    client, token, _data_dir = workspace
    knowledge_id = make_entry(
        client,
        token,
        title="No duplicate summary",
        summary="This sentence should appear once.",
        markdown="# Report\n\nThe actual report body.",
    )
    page = client.get(f"/knowledge/{knowledge_id}").text
    assert page.count("This sentence should appear once.") == 0
    assert "The actual report body." in page


def test_html_fingerprints_static_assets(workspace):
    """HTML references assets by content hash, so new markup never meets cached CSS or JS."""
    client, _token, _data_dir = workspace
    page = client.get("/")
    css = re.search(r'href="[^"]*/static/app\.css\?v=([a-f0-9]{12})"', page.text)
    js = re.search(r'src="[^"]*/static/app\.js\?v=([a-f0-9]{12})"', page.text)
    assert css, "stylesheet URL has no content fingerprint"
    assert js, "JavaScript URL has no content fingerprint"
    # CSS and JS share one fingerprint, so changing either invalidates both.
    assert css.group(1) == js.group(1)


def test_cache_policy_keeps_html_fresh_and_fingerprinted_assets_immutable(workspace):
    client, _token, _data_dir = workspace
    html_page = client.get("/")
    assert html_page.headers["cache-control"] == "no-store"

    match = re.search(r'href="([^"]*/static/app\.css\?v=[a-f0-9]{12})"', html_page.text)
    assert match
    asset = client.get(match.group(1))
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"


def test_templates_do_not_dot_access_dictionary_method_translation_keys():
    """Keys that collide with dict methods (``tr.items``) must use bracket notation."""
    import re
    from pathlib import Path as _Path

    from app.i18n import TRANSLATIONS

    collisions = set(dir(dict)) & set(TRANSLATIONS)
    violations: dict[str, set[str]] = {}
    for template in _Path("app/templates").glob("*.html"):
        body = template.read_text(encoding="utf-8")
        for key in collisions:
            if re.search(r"\btr\." + re.escape(key) + r"\b", body):
                violations.setdefault(template.name, set()).add(key)
    assert not violations, f"translation keys colliding with dict methods must use bracket notation: {violations}"


def test_neutral_slate_text_contrast_meets_wcag_aa():
    """Text colour tokens meet WCAG AA (4.5:1) on every light surface."""
    import re
    from pathlib import Path as _Path

    css = _Path("app/static/app.css").read_text(encoding="utf-8")
    root = css.split("}", 1)[0]
    values = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{3,6})", root))

    def rgb(value: str):
        value = value.lstrip("#")
        if len(value) == 3:
            value = "".join(char * 2 for char in value)
        return [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]

    def luminance(value: str):
        channels = [part / 12.92 if part <= 0.04045 else ((part + 0.055) / 1.055) ** 2.4 for part in rgb(value)]
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    def contrast(left: str, right: str):
        high, low = sorted((luminance(left), luminance(right)), reverse=True)
        return (high + 0.05) / (low + 0.05)

    for text_token in ("text", "muted", "faint", "link"):
        for surface_token in ("surface", "surface-alt", "bg"):
            ratio = contrast(values[text_token], values[surface_token])
            assert ratio >= 4.5, f"--{text_token} on --{surface_token}: {ratio:.2f}:1"


def test_editor_exposes_standard_save_shortcut():
    from pathlib import Path as _Path

    script = _Path("app/static/app.js").read_text(encoding="utf-8")
    template = _Path("app/templates/knowledge_form.html").read_text(encoding="utf-8")
    assert "editor.requestSubmit()" in script
    assert "event.key.toLowerCase() === 's'" in script
    assert 'title="Ctrl+S"' in template


# Program ownership and reference links


def test_deleting_program_keeps_knowledge_as_an_orphan(workspace):
    client, token, data_dir = workspace
    program_id = create_program(client, token, "Disposable Program")
    knowledge_id = create_knowledge(client, token)
    link_finding(client, token, program_id, knowledge_id, "api.disposable.example")

    delete_page = client.get(f"/programs/{program_id}").text
    assert "1 vulnerability." in delete_page
    assert "reusable knowledge and evidence are kept" in delete_page

    response = client.post(f"/programs/{program_id}/delete", data={"csrf": token})
    assert response.status_code == 303
    assert response.headers["location"] == "/knowledge?q=is%3Aorphan"
    assert client.get(f"/programs/{program_id}").status_code == 404

    # Canonical research survives; only the program-specific Finding link is gone.
    knowledge = client.get(f"/knowledge/{knowledge_id}")
    assert knowledge.status_code == 200
    assert "Chiếm quyền tài khoản qua OAuth" in knowledge.text
    findings = client.get("/findings").text
    assert "api.disposable.example" not in findings

    document = (data_dir / "markdown" / f"{knowledge_id}.md").read_text(encoding="utf-8")
    assert "Disposable Program" not in document


def test_finding_can_move_between_programs_without_copying_knowledge(workspace):
    client, token, _data_dir = workspace
    source = create_program(client, token, "Source Program")
    destination = create_program(client, token, "Destination Program")
    knowledge_id = create_knowledge(client, token)
    location = link_bounty_finding(client, token, source, knowledge_id, status="submitted", payout="", bonus="")
    finding_id = location.split("finding_id=")[-1]

    response = client.post(f"/findings/{finding_id}/move", data={"csrf": token, "program_id": destination})
    assert response.status_code == 303
    assert f"program_id={destination}" in response.headers["location"]
    assert f"finding_id={finding_id}" in response.headers["location"]

    source_content = client.get(f"/programs/{source}").text.split('<div class="grid-2', 1)[1]
    destination_content = client.get(f"/programs/{destination}").text.split('<div class="grid-2', 1)[1]
    assert "Chiếm quyền tài khoản qua OAuth" not in source_content
    assert "Chiếm quyền tài khoản qua OAuth" in destination_content
    # The same canonical entry remains; no copy was created.
    knowledge_list = client.get("/knowledge").text
    assert knowledge_list.count("Chiếm quyền tài khoản qua OAuth") == 1


def test_moving_refuses_a_duplicate_program_link(workspace):
    client, token, _data_dir = workspace
    first = create_program(client, token, "First Program")
    second = create_program(client, token, "Second Program")
    knowledge_id = create_knowledge(client, token)
    first_location = link_bounty_finding(client, token, first, knowledge_id, status="submitted", payout="", bonus="")
    link_bounty_finding(client, token, second, knowledge_id, status="submitted", payout="", bonus="")
    first_finding = first_location.split("finding_id=")[-1]

    response = client.post(f"/findings/{first_finding}/move", data={"csrf": token, "program_id": second})
    assert response.status_code == 409


def test_unlinking_a_finding_preserves_its_knowledge(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Unlink Program")
    knowledge_id = create_knowledge(client, token)
    location = link_bounty_finding(client, token, program_id, knowledge_id, status="submitted", payout="", bonus="")
    finding_id = location.split("finding_id=")[-1]

    response = client.post(f"/findings/{finding_id}/delete", data={"csrf": token})
    assert response.status_code == 303
    assert response.headers["location"] == f"/knowledge/{knowledge_id}"
    assert client.get(f"/knowledge/{knowledge_id}").status_code == 200
    assert "Chiếm quyền tài khoản qua OAuth" not in client.get(f"/programs/{program_id}").text


def test_drawer_exposes_program_and_submission_reference_links(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Reference Program")
    create_program(client, token, "Move Destination")
    knowledge_id = create_knowledge(client, token)
    location = link_bounty_finding(
        client,
        token,
        program_id,
        knowledge_id,
        status="submitted",
        payout="",
        bonus="",
        report_url="https://hackerone.com/reports/123456",
        report_id="H1-123456",
    )
    finding_id = location.split("finding_id=")[-1]

    panel = client.get(f"/knowledge/{knowledge_id}/panel?program_id={program_id}&finding_id={finding_id}").text
    assert 'href="https://example.com/program"' in panel
    assert 'href="https://hackerone.com/reports/123456"' in panel
    assert "Open submission" in panel
    assert "H1-123456" in panel
    assert f'action="/findings/{finding_id}/move"' in panel
    assert f'action="/findings/{finding_id}/delete"' in panel
    assert "Keeps the vulnerability as reusable knowledge." in panel


def test_program_url_is_optional_and_rename_is_explicit(workspace):
    client, token, _data_dir = workspace
    response = client.post(
        "/programs/new",
        data={
            "csrf": token,
            "name": "No URL Program",
            "platform": "Independent",
            "handle": "no-url",
            "url": "",
            "notes": "",
        },
    )
    assert response.status_code == 303
    program_id = response.headers["location"].rsplit("/", 1)[-1]

    detail = client.get(f"/programs/{program_id}").text
    assert "Edit program" in detail
    form = client.get(f"/programs/{program_id}/edit").text
    assert "Optional link to the program page." in form
    assert 'name="url" value=""' in form


def test_secondary_ui_sections_use_progressive_disclosure(workspace):
    client, token, _data_dir = workspace

    # A new finding should not confront the user with eight empty bounty fields.
    new_finding = client.get("/findings/new").text
    assert '<details class="form-disclosure" >' in new_finding
    assert '<details class="form-disclosure bounty-editor" >' in new_finding

    program_id = create_program(client, token, "Progressive Program")
    knowledge_id = create_knowledge(client, token)
    location = link_bounty_finding(
        client,
        token,
        program_id,
        knowledge_id,
        status="paid",
        payout="500",
        bonus="50",
    )
    finding_id = location.split("finding_id=")[-1]

    # Existing reward data opens the disclosure automatically; no data stays quiet.
    edit = client.get(f"/findings/{finding_id}/edit").text
    assert '<details class="form-disclosure bounty-editor" open>' in edit

    # Destructive Program deletion is present but collapsed until intentionally opened.
    program = client.get(f"/programs/{program_id}").text
    assert '<details class="danger-disclosure">' in program
    assert "reusable knowledge and evidence are kept" in program


def test_lookup_limits_quick_filters_to_the_actionable_set(workspace):
    client, _token, _data_dir = workspace
    page = client.get("/search").text
    assert page.count('class="preset-chip"') == 4
    for label in ("Needs triage", "Awaiting response", "Accepted, unpaid", "Downgraded"):
        assert label in page


def test_dashboard_combines_secondary_breakdowns(workspace):
    client, token, _data_dir = workspace
    create_knowledge(client, token)
    page = client.get("/").text
    assert 'class="section-label">Breakdown<' in page
    assert 'class="section-label">Status pipeline<' not in page
    assert 'class="section-label">Severity mix<' not in page


def test_findings_registry_summary_and_severity_filter(workspace):
    client, token, _data_dir = workspace
    program_id = create_program(client, token, "Registry Metrics Program")
    cases = [
        ("Critical submitted", "critical", "submitted", ""),
        ("High triaged", "high", "triaged", ""),
        ("High accepted reward", "high", "accepted", "100"),
        ("Low draft", "low", "draft", ""),
    ]
    for title, severity, status, payout in cases:
        knowledge_id = create_knowledge_custom(
            client,
            token,
            title=title,
            default_severity=severity,
        )
        response = client.post(
            "/findings/new",
            data={
                "csrf": token,
                "program_id": program_id,
                "knowledge_id": knowledge_id,
                "target": "api.metrics.example",
                "scope": "API",
                "status": status,
                "severity": severity,
                "payout": payout,
                "currency": "USD",
            },
        )
        assert response.status_code == 303, response.text

    page = client.get("/findings")
    assert page.status_code == 200
    for metric, value in (("total", 4), ("submitted", 2), ("accepted", 1), ("rewarded", 1)):
        assert re.search(rf'data-metric="{metric}"[^>]*>.*?<strong>{value}</strong>', page.text, re.DOTALL)
    assert re.search(r'name="severity" value="critical"[^>]*>.*?<b>1</b>', page.text, re.DOTALL)
    assert re.search(r'name="severity" value="high"[^>]*>.*?<b>2</b>', page.text, re.DOTALL)
    assert "conic-gradient(" in page.text

    filtered = client.get("/findings", params={"severity": "high"})
    assert filtered.status_code == 200
    assert "High triaged" in filtered.text
    assert "High accepted reward" in filtered.text
    assert "Critical submitted" not in filtered.text
    assert 'class="severity-chip high active"' in filtered.text


def test_report_reader_does_not_repeat_structured_sections_already_in_markdown(workspace):
    client, token, _data_dir = workspace
    embedded_id = create_knowledge_custom(
        client,
        token,
        title="Embedded remediation",
        markdown="# Summary\n\nIssue.\n\n## Remediation\n\nMarkdown fix.",
        remediation="Structured fix should be hidden.",
        references="",
    )
    detail = client.get(f"/knowledge/{embedded_id}")
    panel = client.get(f"/knowledge/{embedded_id}/panel")
    assert detail.status_code == 200
    assert panel.status_code == 200
    assert "data-report-reader" in detail.text
    assert 'role="tab" aria-selected="true"' in detail.text
    assert 'role="tabpanel" aria-labelledby="report-tab" aria-hidden="false"' in detail.text
    assert "data-report-reader" in panel.text
    assert 'role="tab" aria-selected="true"' in panel.text
    assert 'role="tabpanel" aria-labelledby="drawer-preview-tab" aria-hidden="false"' in panel.text
    assert "Markdown fix." in detail.text
    assert "Structured fix should be hidden." not in detail.text
    assert "Structured fix should be hidden." not in panel.text

    fallback_id = create_knowledge_custom(
        client,
        token,
        title="Structured remediation fallback",
        markdown="# Summary\n\nIssue without a remediation heading.",
        remediation="Structured fallback remains visible.",
        references="",
    )
    fallback = client.get(f"/knowledge/{fallback_id}")
    assert fallback.status_code == 200
    assert "Structured fallback remains visible." in fallback.text
