"""Tags, the AI export, redaction and the knowledge schema migration."""

import io
import json
import re
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.redaction import RedactionContext, Redactor
from app.taxonomy import normalize_tag, parse_tags


def csrf(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html) or re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert match
    return match.group(1)


def settings_for(tmp_path: Path, name: str = "export.db") -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / name}",
        admin_password="export-password",
        session_secret="export-test-session-secret-at-least-32-characters",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
    )


@pytest.fixture
def ws(tmp_path: Path):
    settings = settings_for(tmp_path)
    with TestClient(create_app(settings), follow_redirects=False) as client:
        login = client.get("/login")
        response = client.post(
            "/login", data={"username": "admin", "password": settings.admin_password, "csrf": csrf(login.text)}
        )
        assert response.status_code == 303
        yield client, csrf(client.get("/").text), tmp_path


def entry(client: TestClient, token: str, title: str, **extra) -> str:
    data = {
        "csrf": token,
        "title": title,
        "bug_type": "Access Control",
        "default_severity": "high",
        "summary": "Missing object-level authorization.",
        "markdown": "# Summary\n\nIDOR.\n\n## Steps to reproduce\n\n1. Request another id.\n",
        "research_notes": "PRIVATE-METHOD-NOTE",
    }
    data.update(extra)
    response = client.post("/knowledge/new", data=data)
    assert response.status_code == 303, response.text
    return response.headers["location"].split("?", 1)[0].rsplit("/", 1)[-1]


def program(client: TestClient, token: str, name: str, handle: str = "") -> str:
    response = client.post(
        "/programs/new", data={"csrf": token, "name": name, "platform": "HackerOne", "handle": handle, "url": ""}
    )
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


def finding(client: TestClient, token: str, program_id: str, knowledge_id: str, target: str) -> None:
    response = client.post(
        "/findings/new",
        data={
            "csrf": token,
            "program_id": program_id,
            "knowledge_id": knowledge_id,
            "target": target,
            "status": "submitted",
            "severity": "high",
        },
    )
    assert response.status_code == 303, response.text


# Tags


def test_tags_are_normalised():
    assert normalize_tag("  Account Takeover ") == "account-takeover"
    assert normalize_tag("lỗ hổng đăng nhập") == "lo-hong-dang-nhap"
    assert normalize_tag("Node.js") == "node.js"
    assert parse_tags("JWT, jwt , GraphQL,,") == ["jwt", "graphql"]
    assert len(parse_tags(",".join(f"t{i}" for i in range(30)))) == 12


def test_tags_are_saved_listed_and_filterable(ws):
    client, token, _ = ws
    tagged = entry(client, token, "Export IDOR", tags="IDOR, Account Takeover, idor")
    entry(client, token, "Plain entry")
    detail = client.get(f"/knowledge/{tagged}").text
    assert ">idor<" in detail and ">account-takeover<" in detail

    listed = client.get("/knowledge", params={"tag": "account-takeover"}).text
    assert "Export IDOR" in listed and "Plain entry" not in listed
    payload = client.get("/api/search", params={"q": "tag:idor"}).json()
    assert [item["title"] for group in payload["groups"] for item in group["items"]] == ["Export IDOR"]
    excluded = client.get("/knowledge", params={"q": "-tag:idor"}).text
    assert "Plain entry" in excluded and "Export IDOR" not in excluded


def test_editing_without_the_tags_field_keeps_tags(ws):
    client, token, _ = ws
    knowledge_id = entry(client, token, "Keeps tags", tags="jwt")
    response = client.post(
        f"/knowledge/{knowledge_id}/edit",
        data={"csrf": token, "title": "Keeps tags", "bug_type": "XSS", "default_severity": "low", "markdown": "# x"},
    )
    assert response.status_code == 303
    assert ">jwt<" in client.get(f"/knowledge/{knowledge_id}").text


def test_tag_rename_merge_and_delete(ws):
    client, token, data_dir = ws
    first = entry(client, token, "First", tags="jwt, auth")
    second = entry(client, token, "Second", tags="json-web-token")
    page = client.get("/knowledge/tags").text
    rename_form = re.search(
        r'/knowledge/tags/(\d+)/rename"[^>]*>\s*<input type="hidden"[^>]*>\s*<input name="name" value="json-web-token"',
        page,
    )
    assert rename_form
    # Renaming onto an existing tag merges the two.
    response = client.post(f"/knowledge/tags/{rename_form.group(1)}/rename", data={"csrf": token, "name": "JWT"})
    assert response.status_code == 303
    page = client.get("/knowledge/tags").text
    assert "json-web-token" not in page
    assert ">jwt<" in client.get(f"/knowledge/{second}").text
    assert "- jwt" in (data_dir / "markdown" / f"{second}.md").read_text(encoding="utf-8")

    auth_id = re.search(r"/knowledge/tags/(\d+)/delete", page.split(">auth<", 1)[1]).group(1)
    assert client.post(f"/knowledge/tags/{auth_id}/delete", data={"csrf": token}).status_code == 303
    assert ">auth<" not in client.get(f"/knowledge/{first}").text


def test_unused_tags_are_pruned(ws):
    client, token, _ = ws
    knowledge_id = entry(client, token, "Temporary tag", tags="one-off")
    client.post(
        f"/knowledge/{knowledge_id}/edit",
        data={"csrf": token, "title": "Temporary tag", "bug_type": "XSS", "default_severity": "low", "tags": ""},
    )
    assert "one-off" not in client.get("/knowledge/tags").text


# Relations


def test_relations_cascade_when_an_entry_is_deleted(ws):
    client, token, data_dir = ws
    target = entry(client, token, "Target entry")
    source = entry(client, token, "Source entry", related_ids=[target])
    assert target in (data_dir / "markdown" / f"{source}.md").read_text(encoding="utf-8")
    assert "Source entry" in client.get(f"/knowledge/{target}").text
    assert client.post(f"/knowledge/{target}/delete", data={"csrf": token}).status_code == 303
    assert target not in (data_dir / "markdown" / f"{source}.md").read_text(encoding="utf-8")
    connection = sqlite3.connect(data_dir / "export.db")
    assert connection.execute("SELECT COUNT(*) FROM knowledge_relations").fetchone()[0] == 0
    connection.close()


# Knowledge editor and programs


def test_new_research_from_a_program_continues_to_the_submission_form(ws):
    client, token, _ = ws
    program_id = program(client, token, "Program Flow")
    response = client.post(
        f"/knowledge/new?program_id={program_id}",
        data={"csrf": token, "title": "From program", "bug_type": "XSS", "default_severity": "high"},
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/findings/new?") and f"program_id={program_id}" in location
    form = client.get(location).text
    assert "selected>Program Flow<" in form.replace("\n", "") or f'value="{program_id}" selected' in form


def test_knowledge_editor_has_no_program_fields(ws):
    client, _token, _ = ws
    page = client.get("/knowledge/new").text
    assert 'name="finding_target"' not in page
    assert 'name="program_id"' not in page
    assert 'name="tags"' in page and 'name="use_for_ai"' in page


# AI export


def test_export_includes_only_entries_marked_for_ai_and_redacts(ws):
    client, token, _ = ws
    program_id = program(client, token, "Acme Payments", handle="acme-pay")
    shared = entry(
        client,
        token,
        "IDOR on Acme Payments export",
        tags="idor, acme-payments",
        markdown=(
            "# Summary\n\nFound on api.acme-pay.com.\n\n## Proof of concept\n\n```http\n"
            "GET /export?access_token=abcdef0123456789 HTTP/1.1\nHost: api.acme-pay.com\n"
            "Cookie: session=0123456789abcdef0123; role=admin\n```\n\nReported by alice@acme-pay.com.\n"
        ),
    )
    finding(client, token, program_id, shared, "https://api.acme-pay.com/v1")
    entry(client, token, "Confidential report", use_for_ai="0")
    client.post("/capture", data={"csrf": token, "title": "Loose draft", "capture": "GET /"})

    payload = json.loads(client.get("/knowledge/export.json").content)
    assert payload["format"] == "vulns-ai-export" and payload["count"] == 1
    document = payload["vulnerabilities"][0]
    assert document["title"] == "IDOR on [program] export"
    assert document["tags"] == ["idor"]
    report = document["report"]
    assert "acme-pay.com" not in report and "target-1.example" in report
    assert "access_token=[REDACTED]" in report and "session=[REDACTED]" in report and "role=admin" in report
    assert "user1@example.com" in report
    assert "PRIVATE-METHOD-NOTE" not in json.dumps(payload)
    assert "research_notes" not in document

    archive = zipfile.ZipFile(io.BytesIO(client.get("/knowledge/export.zip").content))
    names = archive.namelist()
    assert len(names) == 1 and names[0].endswith(".md")
    markdown = archive.read(names[0]).decode("utf-8")
    assert markdown.startswith("---\n") and "IDOR on [program] export" in markdown
    assert "target-1.example" in markdown

    page = client.get("/knowledge/export").text
    assert "Confidential report" in page and "Loose draft" in page


def test_browser_line_endings_are_stored_and_exported_as_lf(ws):
    client, token, data_dir = ws
    knowledge_id = entry(client, token, "CRLF report", markdown="# Summary\r\n\r\nLine one.\r\nLine two.\r\n")
    document = client.get(f"/knowledge/{knowledge_id}/ai.json").json()
    assert "\r" not in document["report"]
    assert "\r" not in (data_dir / "markdown" / f"{knowledge_id}.md").read_text(encoding="utf-8", newline="")


def test_ai_preview_shows_the_redacted_document(ws):
    client, token, _ = ws
    knowledge_id = entry(client, token, "Preview me", use_for_ai="0")
    document = client.get(f"/knowledge/{knowledge_id}/ai.json").json()
    assert document["included"] is False
    assert document["title"] == "Preview me"


def test_redactor_keeps_payload_details_that_matter():
    redactor = Redactor(RedactionContext.build([("Globex", "")], ["admin.globex.io"]))
    text = (
        "SSRF to http://169.254.169.254/latest/ via https://admin.globex.io/fetch.\n"
        "Authorization: Bearer abc.def.ghi\n"
        'payload {"password": "Hunter2!", "token": null}\n'
        "JWT eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.\n"
        "document.cookie stays; see https://owasp.org/www-project-top-ten/ and Globex SSO.\n"
        "AKIAABCDEFGHIJKLMNOP"
    )
    result = redactor.redact(text)
    assert "http://169.254.169.254/latest/" in result
    assert "https://target-1.example/fetch." in result
    assert "Authorization: Bearer [REDACTED]" in result
    assert '"password": "[REDACTED]"' in result and '"token": null' in result
    assert "eyJhbGciOiJub25lIn0.[REDACTED]." in result
    assert "document.cookie" in result and "https://owasp.org/www-project-top-ten/" in result
    assert "[program] SSO" in result
    assert "AKIA" not in result


# Schema migration


def test_legacy_json_columns_migrate_to_tables(tmp_path: Path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE knowledge_entries (
                id VARCHAR(36) PRIMARY KEY, slug VARCHAR(220) NOT NULL UNIQUE, title VARCHAR(240) NOT NULL,
                bug_type VARCHAR(100) NOT NULL, default_severity VARCHAR(20) NOT NULL, tags_json TEXT NOT NULL,
                summary TEXT NOT NULL, markdown TEXT NOT NULL, remediation TEXT NOT NULL, "references" TEXT NOT NULL,
                related_ids_json TEXT NOT NULL DEFAULT '[]', created_at DATETIME, updated_at DATETIME
            );
            INSERT INTO knowledge_entries VALUES
                ('a', 'a', 'Alpha', 'XSS', 'low', '["Stored XSS", "react"]', '', '# A', '', '', '["b", "missing"]',
                 '2026-01-01', '2026-01-01'),
                ('b', 'b', 'Beta', 'XSS', 'low', 'not json', '', '# B', '', '', '[]', '2026-01-01', '2026-01-01');
            """
        )
    settings = settings_for(tmp_path, "legacy.db")
    with TestClient(create_app(settings), follow_redirects=False):
        pass
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(knowledge_entries)")}
        assert "tags_json" not in columns and "related_ids_json" not in columns
        assert "use_for_ai" in columns
        tags = connection.execute(
            "SELECT t.name FROM tags t JOIN knowledge_tags kt ON kt.tag_id = t.id WHERE kt.knowledge_id = 'a' "
            "ORDER BY t.name"
        ).fetchall()
        assert [name for (name,) in tags] == ["react", "stored-xss"]
        assert connection.execute("SELECT source_id, target_id FROM knowledge_relations").fetchall() == [("a", "b")]
