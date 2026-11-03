"""Helpers shared by the routers: page rendering, the database session, sign-in and record loading."""

import hashlib
import re
from pathlib import Path

import bleach
from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markdown_it.common.utils import escapeHtml
from mdit_py_plugins.tasklists import tasklists_plugin
from sqlalchemy.orm import Session, selectinload

from .i18n import TRANSLATIONS, term
from .markdown_store import sync_markdown
from .models import Evidence, Finding, KnowledgeEntry, Program
from .security import authenticated, csrf_token
from .taxonomy import BUG_TYPES, CURRENCIES, CURRENCY_SYMBOLS, DEFAULT_CURRENCY, OUTCOMES, SEVERITIES, STATUSES

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
templates = Jinja2Templates(directory=APP_DIR / "templates")

# Currencies without minor units in everyday use.
WHOLE_CURRENCIES = {"VND", "JPY"}


def format_money(amount: float | None, currency: str = "") -> str:
    """An amount with thousands separators: ``15,000,000`` VND, ``1,250.50`` or ``300`` USD."""
    if amount is None:
        return ""
    if currency in WHOLE_CURRENCIES:
        return f"{amount:,.0f}"
    text = f"{amount:,.2f}"
    return text[:-3] if text.endswith(".00") else text


def format_money_input(amount: float | None) -> str:
    """An amount as a number input expects it: no exponent, no needless ``.0``."""
    if amount is None:
        return ""
    return f"{amount:.0f}" if float(amount).is_integer() else f"{amount:.2f}".rstrip("0")


def format_money_compact(amount: float | None) -> str:
    """A short amount for chart labels: ``850``, ``1.2K``, ``15M``."""
    if not amount:
        return ""
    for size, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(amount) >= size:
            return f"{amount / size:.1f}".removesuffix(".0") + suffix
    return f"{amount:.0f}"


templates.env.filters["money"] = format_money
templates.env.filters["money_input"] = format_money_input
templates.env.filters["money_compact"] = format_money_compact


def report_url(entry: KnowledgeEntry) -> str:
    """Where a report is read: the page of its first vulnerability, or the unfiled list when no program has it."""
    if not entry.findings:
        return "/findings/unfiled"
    return min(entry.findings, key=lambda finding: (finding.created_at, finding.id)).url


def report_edit_url(entry: KnowledgeEntry) -> str:
    """Where a report is edited; an unfiled report can only be filed to a program first."""
    return f"{report_url(entry)}/edit" if entry.findings else "/findings/unfiled"


templates.env.globals["report_url"] = report_url
templates.env.globals["report_edit_url"] = report_edit_url


def _asset_hash() -> str:
    """Appended to asset URLs so a deploy never pairs new HTML with cached CSS or JS."""
    digest = hashlib.sha256()
    for name in ("app.css", "app.js"):
        digest.update((STATIC_DIR / name).read_bytes())
    return digest.hexdigest()[:12]


ASSET_HASH = _asset_hash()

# Evidence types the browser may display; everything else is downloaded. SVG can carry script.
SAFE_INLINE_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "video/mp4",
    "video/webm",
    "audio/mpeg",
    "audio/ogg",
}
EVIDENCE_SRC = re.compile(r"^/evidence/([0-9a-f-]{36})(?:\?.*)?$")
EVIDENCE_REFERENCE = re.compile(r"/evidence/([0-9a-f-]{36})")
TABLE_ALIGNMENT = re.compile(r"^text-align:(left|center|right)$")


def _table_alignment(state) -> None:
    """Turn the inline ``text-align`` style of table cells into a class, since the sanitizer drops styles."""
    for token in state.tokens:
        if token.type in ("th_open", "td_open") and (match := TABLE_ALIGNMENT.match(token.attrGet("style") or "")):
            del token.attrs["style"]
            token.attrSet("class", f"align-{match.group(1)}")


def _render_image(renderer, tokens, idx, options, env) -> str:
    """Images that can be shown inline; attachments and external images otherwise become links.

    ``env["evidence"]`` maps evidence ids to MIME types. External images are linked rather than
    loaded because the Content-Security-Policy blocks third-party requests.
    """
    token = tokens[idx]
    src = token.attrGet("src") or ""
    alt = renderer.renderInlineAsText(token.children or [], options, env)
    title = token.attrGet("title")
    title_attr = f' title="{escapeHtml(title)}"' if title else ""
    match = EVIDENCE_SRC.match(src)
    evidence = env.get("evidence")
    if match and evidence is not None:
        evidence_id = match.group(1)
        mime_type = evidence.get(evidence_id, "")
        url = f"/evidence/{evidence_id}"
        if mime_type in SAFE_INLINE_TYPES and mime_type.startswith("video/"):
            return f'<video controls preload="metadata" src="{url}"{title_attr}></video>'
        if mime_type not in SAFE_INLINE_TYPES or not mime_type.startswith("image/"):
            label = escapeHtml(alt or "attachment")
            return f'<a class="attachment-link" href="{url}?download=true"{title_attr}>{label}</a>'
    elif src.startswith(("http://", "https://")):
        label = escapeHtml(alt or src)
        return f'<a class="external-image" href="{escapeHtml(src)}"{title_attr}>{label}</a>'
    return f'<img src="{escapeHtml(src)}" alt="{escapeHtml(alt)}"{title_attr} loading="lazy">'


MARKDOWN = (
    MarkdownIt("commonmark", {"html": False, "typographer": True})
    .enable(["table", "strikethrough"])
    .use(tasklists_plugin)
)
MARKDOWN.core.ruler.push("table_alignment", _table_alignment)
MARKDOWN.add_render_rule("image", _render_image)
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
    "s",
    "input",
    "img",
    "video",
}
ALLOWED_MARKDOWN_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title", "loading"},
    "video": {"src", "title", "controls", "preload"},
    "input": {"type", "checked", "disabled"},
}
ALLOWED_MARKDOWN_CLASSES = {
    "a": {"attachment-link", "external-image"},
    "th": {"align-left", "align-center", "align-right"},
    "td": {"align-left", "align-center", "align-right"},
}


def _allowed_attribute(tag: str, name: str, value: str) -> bool:
    if name == "class":
        return value in ALLOWED_MARKDOWN_CLASSES.get(tag, ())
    return name in ALLOWED_MARKDOWN_ATTRIBUTES.get(tag, ())


def evidence_types(db: Session, *texts: str) -> dict[str, str]:
    """MIME type of every evidence file referenced as ``/evidence/<id>`` in the given Markdown."""
    ids = {match for text in texts for match in EVIDENCE_REFERENCE.findall(text or "")}
    if not ids:
        return {}
    return dict(db.query(Evidence.id, Evidence.mime_type).filter(Evidence.id.in_(ids)).all())


def render_markdown(value: str, evidence: dict[str, str] | None = None) -> str:
    """Sanitized HTML for a report; pass ``evidence`` (id -> MIME type) to render attachments by type."""
    rendered = MARKDOWN.render(value or "", {"evidence": evidence})
    return bleach.clean(
        rendered,
        tags=ALLOWED_MARKDOWN_TAGS,
        attributes=_allowed_attribute,
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
        "outcomes": OUTCOMES,
        "currency_symbols": CURRENCY_SYMBOLS,
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


def explorer_values(db: Session, current_program_id: str = "") -> dict:
    """The program tree in the sidebar, with the open program highlighted."""
    programs = (
        db.query(Program)
        .options(selectinload(Program.findings).selectinload(Finding.knowledge))
        .order_by(Program.archived, Program.name)
        .all()
    )
    return {"explorer_programs": programs, "explorer_current_program": current_program_id}


def local_path(value: str, fallback: str) -> str:
    """``value`` when it is a path on this site, so a form cannot be used as an open redirect."""
    return value if value.startswith("/") and not value.startswith(("//", "/\\")) else fallback


def refresh_markdown(request: Request, db: Session, *entries: KnowledgeEntry) -> None:
    """Rewrite the Markdown file of each entry from the committed state."""
    # Sessions keep loaded objects across a commit; reload them so a moved or deleted program is not written out.
    db.expire_all()
    for entry in entries:
        sync_markdown(request.app.state.settings.markdown_dir, entry, session=db)
