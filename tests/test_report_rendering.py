"""Markdown reports: GFM tables, strikethrough and attachments rendered by their type."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.web import render_markdown

IMAGE_ID = "11111111-1111-1111-1111-111111111111"
VIDEO_ID = "22222222-2222-2222-2222-222222222222"
SVG_ID = "33333333-3333-3333-3333-333333333333"


def token(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', page)
    assert match
    return match.group(1)


@pytest.fixture
def ws(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        admin_password="report-render-password",
        session_secret="test-session-secret-that-is-long-enough",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        login = client.get("/login")
        client.post(
            "/login", data={"username": "admin", "password": settings.admin_password, "csrf": token(login.text)}
        )
        yield client, token(client.get("/").text)


def test_gfm_table_renders_with_alignment_classes():
    html = render_markdown("| Param | Value | Hits |\n|:--|:-:|--:|\n| `id` | ~~1~~ | 3 |")

    assert "<table>" in html and "<thead>" in html and "<tbody>" in html
    assert '<th class="align-left">Param</th>' in html
    assert '<td class="align-center"><s>1</s></td>' in html
    assert '<td class="align-right">3</td>' in html
    assert "style=" not in html
    assert "|" not in html


def test_table_cells_stay_sanitized():
    html = render_markdown("| a |\n|---|\n| <script>alert(1)</script> <img src=x onerror=alert(1)> |")

    assert "<script" not in html
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_class_attribute_only_accepts_known_values():
    # Raw HTML is disabled, so a class can only come from the renderer itself.
    html = render_markdown('<td class="evil">x</td>')

    assert 'class="evil"' not in html


def test_attachments_render_by_type():
    evidence = {IMAGE_ID: "image/png", VIDEO_ID: "video/mp4", SVG_ID: "image/svg+xml"}
    html = render_markdown(
        f"![shot [1]](/evidence/{IMAGE_ID}) ![clip](/evidence/{VIDEO_ID}) ![logo](/evidence/{SVG_ID})",
        evidence,
    )

    assert f'<img src="/evidence/{IMAGE_ID}" alt="shot [1]" loading="lazy">' in html
    assert f'<video controls preload="metadata" src="/evidence/{VIDEO_ID}"></video>' in html
    assert f'<a class="attachment-link" href="/evidence/{SVG_ID}?download=true">logo</a>' in html
    assert f'<img src="/evidence/{SVG_ID}"' not in html


def test_unknown_evidence_and_external_images_become_links():
    html = render_markdown(
        f"![gone](/evidence/{IMAGE_ID}) ![remote](https://cdn.example.com/x.png)",
        {},
    )

    assert f'href="/evidence/{IMAGE_ID}?download=true"' in html
    assert '<a class="external-image" href="https://cdn.example.com/x.png">remote</a>' in html
    assert "<img" not in html


def test_report_page_and_preview_render_uploaded_attachments(ws):
    client, csrf = ws
    created = client.post(
        "/knowledge/new",
        data={
            "csrf": csrf,
            "title": "Attachment rendering",
            "bug_type": "XSS",
            "default_severity": "medium",
            "markdown": "# Report",
        },
        files=[
            ("uploads", ("proof.png", b"\x89PNG\r\n\x1a\nimage", "image/png")),
            ("uploads", ("clip.mp4", b"\x00\x00\x00\x18ftypmp42", "video/mp4")),
            ("uploads", ("notes.pdf", b"%PDF-1.4", "application/pdf")),
        ],
    )
    knowledge_id = created.headers["location"].rsplit("/", 1)[-1]
    form = client.get(f"/knowledge/{knowledge_id}/edit").text
    ids = dict(re.findall(r'data-url="/evidence/([0-9a-f-]{36})" data-name="([^"]+)"', form))
    by_name = {name: evidence_id for evidence_id, name in ids.items()}
    assert set(by_name) == {"proof.png", "clip.mp4", "notes.pdf"}
    assert 'data-kind="file"' in form and 'data-kind="video"' in form and 'data-kind="image"' in form

    markdown = (
        "| Step | Proof |\n|---|---|\n"
        f"| 1 | ![proof](/evidence/{by_name['proof.png']}) |\n\n"
        f"![clip](/evidence/{by_name['clip.mp4']})\n\n![notes](/evidence/{by_name['notes.pdf']})"
    )
    preview = client.post("/markdown/preview", data={"csrf": csrf, "markdown": markdown})
    assert preview.status_code == 200
    assert f'<td><img src="/evidence/{by_name["proof.png"]}"' in preview.text
    assert f'<video controls preload="metadata" src="/evidence/{by_name["clip.mp4"]}">' in preview.text
    assert f'href="/evidence/{by_name["notes.pdf"]}?download=true">notes</a>' in preview.text

    client.post(
        f"/knowledge/{knowledge_id}/edit",
        data={
            "csrf": csrf,
            "title": "Attachment rendering",
            "bug_type": "XSS",
            "default_severity": "medium",
            "markdown": markdown,
        },
    )
    for url in (f"/knowledge/{knowledge_id}", f"/knowledge/{knowledge_id}/panel"):
        page = client.get(url).text
        assert "<table>" in page
        assert f'<video controls preload="metadata" src="/evidence/{by_name["clip.mp4"]}">' in page
        assert client.get(f"/evidence/{by_name['clip.mp4']}").headers["content-disposition"].startswith("inline")
