"""Helpers shared by the routers: page rendering, the database session, sign-in and record loading."""

import hashlib
from pathlib import Path

import bleach
from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from mdit_py_plugins.tasklists import tasklists_plugin
from sqlalchemy.orm import Session, selectinload

from .i18n import TRANSLATIONS, term
from .markdown_store import sync_markdown
from .models import Finding, KnowledgeEntry, Program
from .security import authenticated, csrf_token
from .taxonomy import BUG_TYPES, CURRENCIES, DEFAULT_CURRENCY, SEVERITIES, STATUSES

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
templates = Jinja2Templates(directory=APP_DIR / "templates")


def _asset_hash() -> str:
    """Appended to asset URLs so a deploy never pairs new HTML with cached CSS or JS."""
    digest = hashlib.sha256()
    for name in ("app.css", "app.js"):
        digest.update((STATIC_DIR / name).read_bytes())
    return digest.hexdigest()[:12]


ASSET_HASH = _asset_hash()

MARKDOWN = MarkdownIt("commonmark", {"html": False, "linkify": True, "typographer": True}).use(tasklists_plugin)
ALLOWED_MARKDOWN_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {
    "p",
    "pre",
    "code",
    "blockquote",
    "hr",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "del",
    "input",
    "img",
}


def render_markdown(value: str) -> str:
    rendered = MARKDOWN.render(value or "")
    return bleach.clean(
        rendered,
        tags=ALLOWED_MARKDOWN_TAGS,
        attributes={"a": ["href", "title"], "img": ["src", "alt", "title"], "input": ["type", "checked", "disabled"]},
        protocols={"http", "https", "mailto"},
        strip=True,
    )


def render(request: Request, template: str, active: str = "", *, status_code: int = 200, **values):
    """Render a page with the values every template relies on; ``active`` marks the navigation item."""
    page = {
        "request": request,
        "layout": "base.html",
        "tr": TRANSLATIONS,
        "active": active,
        "csrf_token": csrf_token(request),
        "asset_hash": ASSET_HASH,
        "severities": SEVERITIES,
        "statuses": STATUSES,
        "bug_types": BUG_TYPES,
        "currencies": CURRENCIES,
        "default_currency": DEFAULT_CURRENCY,
        "humanize": term,
        **values,
    }
    return templates.TemplateResponse(request, template, page, status_code=status_code)


def get_db(request: Request):
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def require_auth(request: Request) -> None:
    if not authenticated(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def get_program(db: Session, program_id: str, *, with_findings: bool = False) -> Program:
    if with_findings:
        item = (
            db.query(Program)
            .options(selectinload(Program.findings).selectinload(Finding.knowledge))
            .filter(Program.id == program_id)
            .first()
        )
    else:
        item = db.get(Program, program_id)
    if not item:
        raise HTTPException(status_code=404)
    return item


def get_knowledge(db: Session, knowledge_id: str) -> KnowledgeEntry:
    item = (
        db.query(KnowledgeEntry)
        .options(
            selectinload(KnowledgeEntry.findings).selectinload(Finding.program),
            selectinload(KnowledgeEntry.evidence),
        )
        .filter(KnowledgeEntry.id == knowledge_id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404)
    return item


def get_finding(db: Session, finding_id: str) -> Finding:
    item = (
        db.query(Finding)
        .options(selectinload(Finding.program), selectinload(Finding.knowledge))
        .filter(Finding.id == finding_id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404)
    return item


def explorer_values(
    db: Session,
    current_program_id: str = "",
    current_knowledge_id: str = "",
    current_finding_id: str = "",
) -> dict:
    """The program tree in the sidebar, with the open record highlighted."""
    programs = (
        db.query(Program)
        .options(selectinload(Program.findings).selectinload(Finding.knowledge))
        .order_by(Program.archived, Program.name)
        .all()
    )
    return {
        "explorer_programs": programs,
        "explorer_current_program": current_program_id,
        "explorer_current_knowledge": current_knowledge_id,
        "explorer_current_finding": current_finding_id,
    }


def refresh_markdown(request: Request, db: Session, *entries: KnowledgeEntry) -> None:
    """Rewrite the Markdown file of each entry."""
    for entry in entries:
        sync_markdown(request.app.state.settings.markdown_dir, entry, session=db)
