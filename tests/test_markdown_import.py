import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Finding, KnowledgeEntry


def csrf(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


@pytest.fixture
def import_workspace(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'import.db'}",
        admin_password="import-password",
        session_secret="markdown-import-test-secret-at-least-32-characters",
        max_upload_bytes=4096,
        secure_cookies=False,
    )
    app = create_app(settings)
    with TestClient(app, follow_redirects=False, raise_server_exceptions=False) as client:
        login = client.get("/login")
        assert (
            client.post(
                "/login", data={"username": "admin", "password": settings.admin_password, "csrf": csrf(login.text)}
            ).status_code
            == 303
        )
        yield client, app, tmp_path


def entries(app) -> list[KnowledgeEntry]:
    with app.state.session_factory() as db:
        return db.query(KnowledgeEntry).order_by(KnowledgeEntry.created_at).all()


def upload(client: TestClient, filename: str, payload: bytes, content_type: str = "text/markdown"):
    page = client.get("/knowledge/import")
    assert page.status_code == 200
    return client.post(
        "/knowledge/import",
        data={"csrf": csrf(page.text)},
        files={"upload": (filename, payload, content_type)},
    )


def test_import_page_and_generic_markdown_create_review_draft(import_workspace):
    client, app, data_dir = import_workspace
    page = client.get("/knowledge")
    assert 'href="/knowledge/import"' in page.text
    import_page = client.get("/knowledge/import")
    assert "Import Markdown" in import_page.text
    assert 'accept=".md,text/markdown"' in import_page.text

    body = b"# Imported SSRF\n\n## Steps to reproduce\n\n1. Request the metadata URL.\n\n```http\nGET /proxy?url=http://169.254.169.254/\n```\n"
    response = upload(client, "ssrf-report.MD", body, "application/octet-stream")
    assert response.status_code == 303
    assert response.headers["location"].endswith("/edit")

    item = entries(app)[0]
    assert item.title == "Imported SSRF"
    assert item.bug_type == "Other"
    assert item.default_severity == "medium"
    assert item.is_draft is True
    assert item.markdown == body.decode()
    assert (data_dir / "markdown" / f"{item.id}.md").exists()

    editor = client.get(response.headers["location"])
    assert editor.status_code == 200
    assert "Imported SSRF" in editor.text
    assert "169.254.169.254" in editor.text


def test_vulns_frontmatter_restores_supported_metadata_only(import_workspace):
    client, app, _data_dir = import_workspace
    document = """---
title: OAuth state confusion
bug_type: OAuth / SSO
severity: critical
summary: State is not bound to the browser session.
endpoint: GET /oauth/callback
technology: OAuth 2.0
cwe: cwe-384
cvss_score: 9.1
research_notes: Private retest method.
remediation: Bind state to the initiating session.
references:
  - https://datatracker.ietf.org/doc/html/rfc6749
program_uses:
  - name: Must not be recreated
---

# Summary

The callback accepts an unrelated state.

## Proof of concept

```http
GET /oauth/callback?state=foreign
```
"""
    response = upload(client, "portable.md", document.encode("utf-8"))
    assert response.status_code == 303

    item = entries(app)[0]
    assert item.title == "OAuth state confusion"
    assert item.bug_type == "OAuth / SSO"
    assert item.default_severity == "critical"
    assert item.summary == "State is not bound to the browser session."
    assert item.endpoint == "GET /oauth/callback"
    assert item.technology == "OAuth 2.0"
    assert item.cwe == "CWE-384"
    assert item.cvss_score == 9.1
    assert item.research_notes == "Private retest method."
    assert item.remediation == "Bind state to the initiating session."
    assert item.references == "https://datatracker.ietf.org/doc/html/rfc6749"
    assert "program_uses" not in item.markdown
    with app.state.session_factory() as db:
        assert db.query(Finding).filter(Finding.knowledge_id == item.id).count() == 0
    assert item.is_draft is True


@pytest.mark.parametrize(
    ("filename", "payload", "expected_status", "message"),
    [
        ("report.txt", b"# Valid Markdown\n", 415, "Only .md files"),
        ("renamed.md", b"plain text with no markdown syntax", 422, "recognizable Markdown"),
        ("invalid.md", b"# Report\n\xff", 415, "UTF-8"),
        ("binary.md", b"# Report\n\x00binary", 415, "binary or unsupported control"),
        ("empty.md", b"", 422, "empty"),
        ("frontmatter.md", b"---\ntitle: [broken\n---\n# Report\n", 422, "frontmatter is invalid"),
        ("unclosed.md", b"---\ntitle: Broken\n# Report\n", 422, "not closed correctly"),
    ],
)
def test_invalid_markdown_uploads_are_rejected_without_writes(
    import_workspace, filename, payload, expected_status, message
):
    client, app, data_dir = import_workspace
    response = upload(client, filename, payload)
    assert response.status_code == expected_status
    assert message in response.text
    assert entries(app) == []
    assert list((data_dir / "markdown").iterdir()) == []


def test_oversized_markdown_is_rejected_before_database_write(import_workspace):
    client, app, data_dir = import_workspace
    payload = b"# Report\n\n```text\n" + (b"x" * 4096) + b"\n```\n"
    response = upload(client, "large.md", payload)
    assert response.status_code == 413
    assert "exceeds the configured upload limit" in response.text
    assert entries(app) == []
    assert list((data_dir / "markdown").iterdir()) == []


def test_markdown_import_requires_valid_csrf(import_workspace):
    client, app, _data_dir = import_workspace
    response = client.post(
        "/knowledge/import",
        data={"csrf": "invalid"},
        files={"upload": ("report.md", b"# Report\n", "text/markdown")},
    )
    assert response.status_code == 403
    assert entries(app) == []
