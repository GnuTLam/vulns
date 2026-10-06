"""Knowledge entries: the vulnerability database."""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import (
    backlink_entries,
    candidate_related_ids,
    index_knowledge,
    push_rediscovery_for_entry,
    remove_knowledge_index,
)
from ..forms import checkbox, entry_text, entry_title, lf, required_text
from ..markdown_import import MarkdownImportError, parse_markdown_upload
from ..markdown_store import delete_markdown, markdown_path, report_roles, unique_slug
from ..models import Finding, KnowledgeEntry, Program
from ..search import compose_query, knowledge_rows, parse_query
from ..security import validate_csrf
from ..stats import draft_count
from ..taxonomy import BUG_TYPES, MAX_TAGS, SEVERITIES, TAG_MAX_LENGTH, normalize_tag, parse_tags
from ..web import (
    explorer_values,
    get_db,
    get_knowledge,
    refresh_markdown,
    render,
    render_markdown,
    require_auth,
)
from .evidence import store_evidence_files
from .tags import assign_tags, prune_tags, tag_counts, tag_names

router = APIRouter(dependencies=[Depends(require_auth)])

# List filter for the AI export, expressed in the query language.
AI_FILTERS = {"included": "is:ai", "excluded": "-is:ai"}
STARTER_REPORT = "\n\n".join(
    (
        "# Summary",
        "## Steps to reproduce",
        "1. ",
        "## Proof of concept",
        "```http\n\n```",
        "## Impact",
        "## Remediation\n",
    )
)


def related_entries(entry: KnowledgeEntry) -> list[KnowledgeEntry]:
    return sorted(entry.related, key=lambda item: (item.title, item.id))


def backlink_only_entries(db: Session, entry: KnowledgeEntry) -> list[KnowledgeEntry]:
    """Entries that link to this one without a link back; mutual links appear under Related."""
    forward = set(entry.related_ids)
    return [item for item in backlink_entries(db, entry.id) if item.id not in forward]


def entries_by_id(db: Session, ids: list[str], current_id: str = "") -> list[KnowledgeEntry]:
    requested = {item for item in ids if item and item != current_id}
    if not requested:
        return []
    return db.query(KnowledgeEntry).filter(KnowledgeEntry.id.in_(requested)).all()


def rediscovery_for_entry(db: Session, entry: KnowledgeEntry) -> list[dict]:
    """Related prior research for an entry, excluding entries already linked either way."""
    known = set(entry.related_ids)
    known.update(item.id for item in backlink_entries(db, entry.id))
    return push_rediscovery_for_entry(db, entry, limit=5, exclude_ids=known)


def owned_finding(db: Session, finding_id: str, entry: KnowledgeEntry, program_id: str = "") -> Finding | None:
    """Return the finding only if it belongs to this entry (and to the program, when given)."""
    if not finding_id:
        return None
    finding = db.get(Finding, finding_id)
    if not finding or finding.knowledge_id != entry.id:
        return None
    if program_id and finding.program_id != program_id:
        return None
    return finding


@router.get("/knowledge", response_class=HTMLResponse)
def knowledge_list(
    request: Request,
    q: str = "",
    severity: str = "",
    bug_type: str = "",
    tag: str = "",
    ai: str = "",
    draft: str = "",
    db: Session = Depends(get_db),
):
    # Dropdown filters are folded into the query language so this list uses the search engine.
    selected_tag = normalize_tag(tag)
    effective = compose_query(
        q,
        severity=severity if severity in SEVERITIES else "",
        type=bug_type if bug_type in BUG_TYPES else "",
        tag=selected_tag,
    )
    if ai in AI_FILTERS:
        effective = f"{effective} {AI_FILTERS[ai]}".strip()
    if draft == "1":
        effective = f"{effective} is:draft".strip()
    parsed = parse_query(effective)
    items, result_total, _ranked = knowledge_rows(db, parsed, limit=500)
    return render(
        request,
        "knowledge.html",
        "knowledge",
        entries=items,
        q=q,
        selected_severity=severity,
        selected_bug_type=bug_type,
        selected_tag=selected_tag,
        selected_ai=ai if ai in AI_FILTERS else "",
        selected_draft=draft,
        draft_count=draft_count(db),
        tag_options=tag_counts(db),
        result_total=result_total,
        query_warnings=parsed.warnings,
    )


def _import_page(request: Request, error: str = "", status_code: int = 200):
    return render(
        request,
        "knowledge_import.html",
        "knowledge",
        error=error,
        max_upload_bytes=request.app.state.settings.max_upload_bytes,
        status_code=status_code,
    )


@router.get("/knowledge/import", response_class=HTMLResponse)
def knowledge_import_page(request: Request):
    return _import_page(request)


@router.post("/knowledge/import", response_class=HTMLResponse)
async def knowledge_import(
    request: Request,
    upload: UploadFile = File(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    limit = request.app.state.settings.max_upload_bytes
    payload = bytearray()
    while chunk := await upload.read(64 * 1024):
        payload.extend(chunk)
        if len(payload) > limit:
            return _import_page(request, "The Markdown file exceeds the configured upload limit.", 413)
    try:
        imported = parse_markdown_upload(
            upload.filename or "", bytes(payload), bug_types=BUG_TYPES, severities=SEVERITIES
        )
    except MarkdownImportError as exc:
        return _import_page(request, str(exc), exc.status_code)

    item = KnowledgeEntry(
        title=imported.title,
        slug=unique_slug(db, imported.title),
        bug_type=imported.bug_type,
        default_severity=imported.default_severity,
        summary=imported.summary,
        endpoint=imported.endpoint,
        technology=imported.technology,
        cwe=imported.cwe,
        cvss_score=imported.cvss_score,
        research_notes=imported.research_notes,
        markdown=imported.markdown,
        remediation=imported.remediation,
        references=imported.references,
        use_for_ai=imported.use_for_ai,
        is_draft=True,
    )
    db.add(item)
    db.flush()
    assign_tags(db, item, imported.tags)
    index_knowledge(db, item)
    db.commit()
    refresh_markdown(request, db, item)
    return RedirectResponse(f"/knowledge/{item.id}/edit", status_code=303)


@router.get("/knowledge/new", response_class=HTMLResponse)
def knowledge_new_page(request: Request, program_id: str = "", db: Session = Depends(get_db)):
    return render(
        request,
        "knowledge_form.html",
        "programs" if program_id else "knowledge",
        entry=None,
        starter=STARTER_REPORT,
        form_action="/knowledge/new" + (f"?{urlencode({'program_id': program_id})}" if program_id else ""),
        tag_options=tag_names(db),
        max_tags=MAX_TAGS,
        tag_max_length=TAG_MAX_LENGTH,
        relation_entries=db.query(KnowledgeEntry).order_by(KnowledgeEntry.title).all(),
        related_ids=[],
        editor_back_url=f"/programs/{program_id}" if program_id else "/knowledge",
        **(explorer_values(db, current_program_id=program_id) if program_id else {}),
    )


@router.post("/knowledge/new")
async def knowledge_create(
    request: Request,
    title: str = Form(...),
    bug_type: str = Form(...),
    default_severity: str = Form(...),
    summary: str = Form(""),
    endpoint: str = Form(""),
    technology: str = Form(""),
    cwe: str = Form(""),
    cvss_score: str = Form(""),
    research_notes: str = Form(""),
    tags: str = Form(""),
    use_for_ai: list[str] | None = Form(None),
    related_ids: list[str] = Form([]),
    markdown: str = Form(""),
    remediation: str = Form(""),
    references: str = Form(""),
    csrf: str = Form(...),
    uploads: list[UploadFile] | None = File(None),
    program_id: str = "",
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    clean_title = entry_title(title, bug_type, default_severity)
    item = KnowledgeEntry(
        title=clean_title,
        slug=unique_slug(db, clean_title),
        bug_type=bug_type,
        default_severity=default_severity,
        **entry_text(
            summary=summary,
            endpoint=endpoint,
            technology=technology,
            cwe=cwe,
            cvss_score=cvss_score,
            research_notes=research_notes,
            markdown=markdown,
            remediation=remediation,
            references=references,
        ),
        use_for_ai=checkbox(use_for_ai) is not False,
    )
    db.add(item)
    db.flush()
    assign_tags(db, item, tags)
    item.related = entries_by_id(db, related_ids, current_id=item.id)
    await store_evidence_files(request, db, item, uploads)
    index_knowledge(db, item)
    db.commit()
    # Entries this one links to list it under referenced_by.
    refresh_markdown(request, db, item, *related_entries(item))
    program = db.get(Program, program_id) if program_id else None
    if program and not program.archived:
        # Started from a program page: continue by recording the submission there.
        query = urlencode({"knowledge_id": item.id, "program_id": program.id})
        return RedirectResponse(f"/findings/new?{query}", status_code=303)
    return RedirectResponse(f"/knowledge/{item.id}", status_code=303)


@router.get("/capture", response_class=HTMLResponse)
def quick_capture_page(request: Request, db: Session = Depends(get_db)):
    """Minimal form for saving a finding mid-hunt."""
    return render(request, "capture.html", "knowledge", draft_count=draft_count(db))


@router.post("/capture")
def quick_capture_create(
    request: Request,
    title: str = Form(...),
    capture: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    """Save a pasted request/response as a draft entry inside an ``http`` code block."""
    validate_csrf(request, csrf)
    clean_title = required_text(title, "Title", 240)
    pasted = lf(capture.strip())
    body = f"# {clean_title}\n"
    if pasted:
        body += f"\n## Captured request / response\n\n```http\n{pasted}\n```\n"
    item = KnowledgeEntry(
        title=clean_title,
        slug=unique_slug(db, clean_title),
        bug_type="Other",
        default_severity="medium",
        summary="",
        markdown=body,
        is_draft=True,
    )
    db.add(item)
    db.flush()
    index_knowledge(db, item)
    db.commit()
    refresh_markdown(request, db, item)
    return RedirectResponse(f"/knowledge/{item.id}", status_code=303)


@router.get("/knowledge/{knowledge_id}", response_class=HTMLResponse)
def knowledge_detail(
    request: Request,
    knowledge_id: str,
    program_id: str = "",
    finding_id: str = "",
    db: Session = Depends(get_db),
):
    item = get_knowledge(db, knowledge_id)
    return render(
        request,
        "knowledge_detail.html",
        "programs" if program_id else "knowledge",
        entry=item,
        rendered=render_markdown(item.markdown),
        report_roles=report_roles(item.markdown),
        related=related_entries(item),
        backlinks=backlink_only_entries(db, item),
        rediscover=rediscovery_for_entry(db, item),
        context_program_id=program_id,
        context_finding_id=finding_id,
        **(explorer_values(db, program_id, knowledge_id, finding_id) if program_id else {}),
    )


@router.get("/knowledge/{knowledge_id}/panel", response_class=HTMLResponse)
def knowledge_panel(
    request: Request,
    knowledge_id: str,
    program_id: str = "",
    finding_id: str = "",
    db: Session = Depends(get_db),
):
    """Record drawer fragment without a layout; app.js injects it into the drawer."""
    item = get_knowledge(db, knowledge_id)
    program_finding = owned_finding(db, finding_id, item, program_id)
    if not program_finding and program_id:
        program_finding = (
            db.query(Finding).filter(Finding.program_id == program_id, Finding.knowledge_id == item.id).first()
        )
    query = f"?program_id={program_id}&finding_id={finding_id}" if program_id else ""
    return render(
        request,
        "_record_drawer.html",
        entry=item,
        rendered=render_markdown(item.markdown),
        report_roles=report_roles(item.markdown),
        program_finding=program_finding,
        move_programs=[
            program
            for program in db.query(Program).filter(Program.archived.is_(False)).order_by(Program.name).all()
            if not program_finding or program.id != program_finding.program_id
        ],
        full_url=f"/knowledge/{item.id}{query}",
        edit_url=f"/knowledge/{item.id}/edit{query}{'&' if query else '?'}embed=1",
    )


@router.get("/knowledge/{knowledge_id}/edit", response_class=HTMLResponse)
def knowledge_edit_page(
    request: Request,
    knowledge_id: str,
    program_id: str = "",
    finding_id: str = "",
    embed: int = 0,
    db: Session = Depends(get_db),
):
    item = get_knowledge(db, knowledge_id)
    record_query = urlencode({"program_id": program_id, "finding_id": finding_id}) if program_id else ""
    # Embedded in the drawer: no app shell and no explorer query.
    explorer = explorer_values(db, program_id, knowledge_id, finding_id) if program_id and not embed else {}
    return render(
        request,
        "knowledge_form.html",
        "programs" if program_id else "knowledge",
        layout="embed.html" if embed else "base.html",
        embed=bool(embed),
        entry=item,
        form_action=f"/knowledge/{item.id}/edit" + (f"?{record_query}" if record_query else ""),
        tag_options=tag_names(db),
        max_tags=MAX_TAGS,
        tag_max_length=TAG_MAX_LENGTH,
        relation_entries=db.query(KnowledgeEntry)
        .filter(KnowledgeEntry.id != item.id)
        .order_by(KnowledgeEntry.title)
        .all(),
        related_ids=item.related_ids,
        editor_back_url=(
            f"/knowledge/{item.id}?{record_query}" if program_id and finding_id else f"/knowledge/{item.id}"
        ),
        **explorer,
    )


@router.post("/knowledge/{knowledge_id}/edit")
async def knowledge_edit(
    request: Request,
    knowledge_id: str,
    title: str = Form(...),
    bug_type: str = Form(...),
    default_severity: str = Form(...),
    summary: str = Form(""),
    endpoint: str = Form(""),
    technology: str = Form(""),
    cwe: str = Form(""),
    cvss_score: str = Form(""),
    research_notes: str = Form(""),
    tags: str | None = Form(None),
    use_for_ai: list[str] | None = Form(None),
    related_ids: list[str] = Form([]),
    markdown: str = Form(""),
    remediation: str = Form(""),
    references: str = Form(""),
    csrf: str = Form(...),
    uploads: list[UploadFile] | None = File(None),
    program_id: str = "",
    finding_id: str = "",
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    clean_title = entry_title(title, bug_type, default_severity)
    item = get_knowledge(db, knowledge_id)
    previously_related = list(item.related)
    item.title, item.slug = clean_title, unique_slug(db, clean_title, current_id=item.id)
    item.bug_type, item.default_severity = bug_type, default_severity
    text = entry_text(
        summary=summary,
        endpoint=endpoint,
        technology=technology,
        cwe=cwe,
        cvss_score=cvss_score,
        research_notes=research_notes,
        markdown=markdown,
        remediation=remediation,
        references=references,
    )
    for name, value in text.items():
        setattr(item, name, value)
    # Saving the full form completes triage, so a quick-capture draft becomes a regular entry.
    item.is_draft = False
    if (flag := checkbox(use_for_ai)) is not None:
        item.use_for_ai = flag
    if tags is not None:
        assign_tags(db, item, tags)
    item.related = entries_by_id(db, related_ids, current_id=item.id)
    await store_evidence_files(request, db, item, uploads)
    index_knowledge(db, item)
    prune_tags(db)
    db.commit()
    # Entries linked before or after this save have a changed referenced_by list.
    linked = {entry.id: entry for entry in [*previously_related, *item.related]}
    refresh_markdown(request, db, item, *linked.values())
    destination = f"/knowledge/{item.id}"
    finding = owned_finding(db, finding_id, item, program_id) if program_id else None
    if finding:
        destination += "?" + urlencode({"program_id": finding.program_id, "finding_id": finding.id})
    return RedirectResponse(destination, status_code=303)


@router.post("/knowledge/{knowledge_id}/copy")
def knowledge_copy(request: Request, knowledge_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    source = get_knowledge(db, knowledge_id)
    copy = KnowledgeEntry(
        title=f"{source.title} (Copy)",
        slug=unique_slug(db, f"{source.title} copy"),
        bug_type=source.bug_type,
        default_severity=source.default_severity,
        summary=source.summary,
        endpoint=source.endpoint,
        technology=source.technology,
        cwe=source.cwe,
        cvss_score=source.cvss_score,
        research_notes=source.research_notes,
        markdown=source.markdown,
        remediation=source.remediation,
        references=source.references,
        use_for_ai=source.use_for_ai,
    )
    db.add(copy)
    db.flush()
    copy.tags = list(source.tags)
    copy.related = [source, *source.related]
    index_knowledge(db, copy)
    db.commit()
    # The copy links to the source and its related entries; refresh their referenced_by.
    refresh_markdown(request, db, copy, *related_entries(copy))
    return RedirectResponse(f"/knowledge/{copy.id}/edit", status_code=303)


@router.post("/knowledge/{knowledge_id}/delete")
def knowledge_delete(request: Request, knowledge_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    settings = request.app.state.settings
    item = get_knowledge(db, knowledge_id)
    evidence_paths = [settings.evidence_dir / evidence.stored_name for evidence in item.evidence]
    # Entries linked in either direction need their Markdown refreshed afterwards.
    affected = {entry.id: entry for entry in [*item.related, *backlink_entries(db, item.id)]}
    remove_knowledge_index(db, item.id)
    delete_markdown(settings.markdown_dir, item)
    db.delete(item)
    db.flush()
    prune_tags(db)
    db.commit()
    db.expire_all()
    # Remove files only after the commit succeeds.
    for path in evidence_paths:
        path.unlink(missing_ok=True)
    refresh_markdown(request, db, *affected.values())
    return RedirectResponse("/knowledge", status_code=303)


@router.get("/knowledge/{knowledge_id}/markdown")
def knowledge_download(request: Request, knowledge_id: str, db: Session = Depends(get_db)):
    item = get_knowledge(db, knowledge_id)
    refresh_markdown(request, db, item)
    return FileResponse(
        markdown_path(request.app.state.settings.markdown_dir, item),
        media_type="text/markdown; charset=utf-8",
        filename=f"{item.slug}.md",
    )


@router.post("/markdown/preview", response_class=HTMLResponse)
def markdown_preview(request: Request, markdown: str = Form(""), csrf: str = Form(...)):
    validate_csrf(request, csrf)
    return HTMLResponse(render_markdown(markdown))


@router.post("/knowledge/candidates")
def knowledge_candidates(
    request: Request,
    csrf: str = Form(...),
    current_id: str = Form(""),
    cwe: str = Form(""),
    bug_type: str = Form(""),
    technology: str = Form(""),
    title: str = Form(""),
    summary: str = Form(""),
    tags: str = Form(""),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    candidates = candidate_related_ids(
        db,
        current_id=current_id.strip(),
        cwe=cwe,
        bug_type=bug_type,
        technology=technology,
        title=title,
        summary=summary,
        tags=parse_tags(tags),
    )
    return {"candidates": candidates}
