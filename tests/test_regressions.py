"""Regression tests for search parsing, Markdown import, deletion, record ownership and page behaviour."""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.markdown_import import MarkdownImportError, parse_markdown_upload
from app.models import KnowledgeEntry
from app.routes import programs as program_routes
from app.search import parse_query


def token(page: str) -> str:
    match = re.search(r'name="csrf-token" content="([^"]+)"', page) or re.search(r'name="csrf" value="([^"]+)"', page)
    assert match
    return match.group(1)


@pytest.fixture
def ws(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'review.db'}",
        admin_password="review-password",
        session_secret="review-test-session-secret-at-least-32-characters",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
    )
    app = create_app(settings)
    with TestClient(app, follow_redirects=False, raise_server_exceptions=False) as client:
        login = client.get("/login")
        assert (
            client.post(
                "/login", data={"username": "admin", "password": settings.admin_password, "csrf": token(login.text)}
            ).status_code
            == 303
        )
        yield client, token(client.get("/").text), tmp_path


def entry(client: TestClient, csrf: str, title: str, **extra) -> str:
    data = {
        "csrf": csrf,
        "title": title,
        "bug_type": "XSS",
        "default_severity": "high",
        "summary": "",
        "endpoint": "",
        "technology": "",
        "cwe": "",
        "cvss_score": "",
        "research_notes": "",
        "program_id": "",
        "markdown": "# Report\n\nBody.",
        "remediation": "",
        "references": "",
    }
    data.update(extra)
    response = client.post("/knowledge/new", data=data)
    assert response.status_code == 303, response.text
    return response.headers["location"].split("/")[2]


def program(client: TestClient, csrf: str, name: str) -> tuple[int, str]:
    response = client.post(
        "/programs/new", data={"csrf": csrf, "name": name, "platform": "", "url": "", "handle": "", "notes": ""}
    )
    return response.status_code, response.headers.get("location", "").rsplit("/", 1)[-1]


def finding(client: TestClient, csrf: str, program_id: str, knowledge_id: str, **extra) -> str:
    data = {
        "csrf": csrf,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "target": "",
        "scope": "",
        "status": "submitted",
        "severity": "high",
        "report_id": "",
        "report_url": "",
        "submitted_at": "",
        "payout": "",
        "private_notes": "",
    }
    data.update(extra)
    response = client.post("/findings/new", data=data)
    assert response.status_code == 303, response.text
    return re.search(r"finding_id=([0-9a-f-]{36})", response.headers["location"]).group(1)


def titles(client: TestClient, query: str) -> set[str]:
    payload = client.get("/api/search", params={"q": query, "limit": 15}).json()
    return {item["title"] for group in payload["groups"] for item in group["items"]}


def test_duplicate_non_ascii_program_name_is_a_conflict_not_a_crash(ws):
    client, csrf, _ = ws
    assert program(client, csrf, "Équipe")[0] == 303
    assert program(client, csrf, "équipe")[0] == 409


def test_negated_field_filters_exclude_matches(ws):
    client, csrf, _ = ws
    entry(client, csrf, "Java deserialization", technology="Java")
    entry(client, csrf, "Python pickle", technology="Python")
    assert titles(client, "-tech:java") == {"Python pickle"}


def test_negated_kind_and_numeric_ranges(ws):
    client, csrf, _ = ws
    entry(client, csrf, "Alpha low", cvss_score="3")
    entry(client, csrf, "Alpha mid", cvss_score="6")
    entry(client, csrf, "Alpha top", cvss_score="9")
    assert parse_query("-kind:program alpha").kinds == ("knowledge", "finding")
    assert titles(client, "cvss:>=5 cvss:<=8") == {"Alpha mid"}
    assert titles(client, "alpha -cvss:>5") == {"Alpha low"}


def test_punctuation_and_empty_phrases_do_not_change_results(ws):
    client, csrf, _ = ws
    entry(client, csrf, "Alpha entry")
    entry(client, csrf, "Beta entry")
    assert titles(client, "alpha &") == {"Alpha entry"}
    assert parse_query('""').is_empty


def test_yaml_alias_bomb_is_refused():
    bomb = (
        b"---\na: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        b"references: [*b,*b,*b]\n---\n# Title\n\nBody text.\n"
    )
    with pytest.raises(MarkdownImportError):
        parse_markdown_upload("bomb.md", bomb, bug_types=("Other",), severities=("medium",))


def test_deleting_an_entry_removes_it_from_entries_that_link_to_it(ws):
    client, csrf, data_dir = ws
    target = entry(client, csrf, "Target entry")
    source = entry(client, csrf, "Source entry", related_ids=[target])
    assert target in (data_dir / "markdown" / f"{source}.md").read_text(encoding="utf-8")
    assert client.post(f"/knowledge/{target}/delete", data={"csrf": csrf}).status_code == 303
    assert target not in (data_dir / "markdown" / f"{source}.md").read_text(encoding="utf-8")


def test_drawer_ignores_a_finding_that_belongs_to_another_entry(ws):
    client, csrf, _ = ws
    _status, program_id = program(client, csrf, "Owner Co")
    mine = entry(client, csrf, "Mine")
    other = entry(client, csrf, "Other")
    response = client.post(
        "/findings/new",
        data={
            "csrf": csrf,
            "program_id": program_id,
            "knowledge_id": other,
            "target": "secret-target.example",
            "scope": "",
            "status": "submitted",
            "severity": "high",
            "report_id": "OTHER-1",
            "report_url": "",
            "submitted_at": "",
            "payout": "",
            "private_notes": "",
        },
    )
    assert response.status_code == 303
    page = client.get(f"/programs/{program_id}").text
    other_finding = re.search(r"finding_id=([0-9a-f-]{36})", page).group(1)
    panel = client.get(f"/knowledge/{mine}/panel?finding_id={other_finding}").text
    assert "secret-target.example" not in panel
    assert other_finding not in panel


def test_dashboard_counts_agree_with_the_lists_they_link_to(ws):
    client, csrf, _ = ws
    _status, program_id = program(client, csrf, "Count Co")
    knowledge_id = entry(client, csrf, "Accepted, zero payout")
    response = client.post(
        "/findings/new",
        data={
            "csrf": csrf,
            "program_id": program_id,
            "knowledge_id": knowledge_id,
            "target": "t.example",
            "scope": "",
            "status": "accepted",
            "severity": "high",
            "report_id": "",
            "report_url": "",
            "submitted_at": "",
            "payout": "0",
            "private_notes": "",
        },
    )
    assert response.status_code == 303
    page = client.get("/").text
    assert re.search(r'data-dashboard-metric="open"[^>]*>.*?<strong>1</strong>', page, re.DOTALL)
    assert re.search(r'data-dashboard-metric="rewarded"[^>]*>.*?<strong>1</strong>', page, re.DOTALL)


def test_the_api_schema_is_not_published(ws):
    client, _csrf, _ = ws
    assert client.get("/openapi.json").status_code == 404


def test_enter_in_the_finding_form_saves_instead_of_unlinking(ws):
    client, csrf, _ = ws
    _status, program_id = program(client, csrf, "Enter Co")
    finding_id = finding(client, csrf, program_id, entry(client, csrf, "Enter key"))
    page = client.get(f"/findings/{finding_id}/edit").text
    edit_form = re.search(r'<form method="post" action="/findings/[^"]+/edit">(.*?)</form>', page, re.S).group(1)
    # Enter in a field presses the first submit button that belongs to the form.
    own_buttons = [
        button
        for button in re.findall(r"<button[^>]*>.*?</button>", edit_form, re.S)
        if 'type="submit"' in button and ' form="' not in button
    ]
    assert ">Save<" in own_buttons[0]
    assert f'<form id="unlink-form" method="post" action="/findings/{finding_id}/delete" data-confirm=' in page


def test_findings_severity_filter_survives_the_other_filters(ws):
    client, _csrf, _ = ws
    page = client.get("/findings", params={"severity": "high", "q": "token"}).text
    controls = re.search(r'<form class="finding-controls".*?</form>', page, re.S).group(0)
    assert 'name="severity" value="high" checked' in controls
    # Severity travels as the checked radio, so the only submit button is the Filter button.
    assert controls.count('type="submit"') == 1


def test_drawer_and_form_show_the_same_response_times(ws):
    client, csrf, _ = ws
    _status, program_id = program(client, csrf, "Resolve Co")
    knowledge_id = entry(client, csrf, "Resolved without triage")
    finding_id = finding(client, csrf, program_id, knowledge_id, submitted_at="2026-01-01", resolved_at="2026-01-11")
    panel = client.get(f"/knowledge/{knowledge_id}/panel?program_id={program_id}&finding_id={finding_id}").text
    form = client.get(f"/findings/{finding_id}/edit").text
    for page in (panel, form):
        assert re.search(r'Days to resolve</p>\s*<p class="v num">10</p>', page)


def test_entry_with_only_backlinks_has_no_empty_related_list(ws):
    client, csrf, _ = ws
    target = entry(client, csrf, "Linked to")
    entry(client, csrf, "Links out", related_ids=[target])
    page = client.get(f"/knowledge/{target}").text
    assert "Referenced by" in page and "Links out" in page
    assert "Related vulnerabilities" not in page


def test_drawer_editor_can_ask_for_confirmation(ws):
    client, csrf, _ = ws
    knowledge_id = entry(client, csrf, "Embedded editor")
    assert 'id="confirm-dialog"' in client.get(f"/knowledge/{knowledge_id}/edit?embed=1").text


def test_list_pages_report_unknown_filters(ws):
    client, _csrf, _ = ws
    for path in ("/knowledge", "/findings"):
        page = client.get(path, params={"q": "sevv:high"}).text
        assert "Unrecognised filter" in page and "<code>sevv</code>" in page


def test_program_rediscovery_uses_the_most_recent_research(ws, monkeypatch):
    client, csrf, _ = ws
    _status, program_id = program(client, csrf, "Order Co")
    entry_ids = [entry(client, csrf, f"Entry {index}") for index in range(10)]
    for entry_id in entry_ids:
        finding(client, csrf, program_id, entry_id)
    with client.app.state.session_factory() as db:
        for day, entry_id in enumerate(entry_ids, start=1):
            db.get(KnowledgeEntry, entry_id).updated_at = datetime(2026, 1, day, tzinfo=UTC)
        db.commit()
    signals: dict = {}
    monkeypatch.setattr(
        program_routes, "push_rediscovery_for_signals", lambda _db, **values: signals.update(values) or []
    )
    assert client.get(f"/programs/{program_id}").status_code == 200
    assert signals["title"] == " ".join(f"Entry {index}" for index in range(9, 1, -1))
