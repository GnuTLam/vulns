"""Vulnerabilities: a finding with its report, and the pages and actions around them."""

from collections import Counter
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..forms import (
    BountyRecord,
    ReportRecord,
    SubmissionRecord,
    bounty_fields,
    checkbox,
    report_fields,
    submission_fields,
)
from ..markdown_import import MarkdownImportError, parse_markdown_upload
from ..markdown_store import markdown_path, report_roles
from ..models import Finding, KnowledgeEntry, Program
from ..search import compose_query, finding_rows, parse_query
from ..security import validate_csrf
from ..stats import earnings_report, unfiled_count
from ..taxonomy import BUG_TYPES, MAX_TAGS, SEVERITIES, STATUSES, TAG_MAX_LENGTH
from ..vulns import (
    backlink_only_entries,
    create_vulnerability,
    delete_report,
    delete_vulnerability,
    duplicate_vulnerability,
    file_report,
    import_report,
    open_program,
    record_bounty,
    rediscovery_for_entry,
    related_entries,
    set_paid,
    set_status,
    unfiled_entries,
    update_vulnerability,
)
from ..web import (
    evidence_types,
    get_db,
    get_finding,
    get_knowledge,
    local_path,
    refresh_markdown,
    render,
    render_markdown,
    require_auth,
)
from .evidence import store_evidence_files
from .tags import tag_names

router = APIRouter(dependencies=[Depends(require_auth)])

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


def _open_programs(db: Session) -> list[Program]:
    return db.query(Program).filter(Program.archived.is_(False)).order_by(Program.name).all()


def _bounty_link(program_id: str, year: int | None, currency: str):
    """Builds links to the bounty tab that keep the filters in force, changing only what is passed."""

    def link(**changes: object) -> str:
        values = {"year": "all" if year is None else year, "currency": currency, "program_id": program_id, **changes}
        return "/findings?" + urlencode({"tab": "bounty", **{key: value for key, value in values.items() if value}})

    return link


@router.get("/findings", response_class=HTMLResponse)
def findings_list(
    request: Request,
    tab: str = "",
    q: str = "",
    status: str = "",
    severity: str = "",
    program_id: str = "",
    year: str = "",
    currency: str = "",
    db: Session = Depends(get_db),
):
    """The vulnerability list, or with ``tab=bounty`` the bounty statistics and rewards ledger."""
    programs = db.query(Program).order_by(Program.name).all()
    common = {"programs": programs, "selected_program": program_id, "unfiled_count": unfiled_count(db)}
    if tab == "bounty":
        report = earnings_report(db, year.strip(), currency.strip().upper(), program_id)
        link = _bounty_link(program_id, report["selected_year"], report["selected_currency"])
        return render(request, "findings.html", "findings", tab="bounty", bounty_link=link, **common, **report)

    parsed = parse_query(compose_query(q, severity=severity if severity in SEVERITIES else "", program_id=program_id))
    matching, _total, _ranked = finding_rows(db, parsed, limit=1200)
    status_counts = Counter(finding.status for finding in matching)
    selected_status = status if status in STATUSES else ""
    items = [finding for finding in matching if not selected_status or finding.status == selected_status]
    return render(
        request,
        "findings.html",
        "findings",
        tab="reports",
        findings=items[:500],
        q=q,
        selected_status=selected_status,
        selected_severity=severity,
        result_total=len(items),
        status_counts=status_counts,
        match_total=len(matching),
        query_warnings=parsed.warnings,
        **common,
    )


def _editor_values(db: Session, finding: Finding | None = None, program_id: str = "") -> dict:
    """Values for the vulnerability form, which creates a vulnerability or edits an existing one."""
    entry = finding.knowledge if finding else None
    programs = _open_programs(db)
    if finding and finding.program.archived:
        # A vulnerability stays selectable in the program it was filed under after that is archived.
        programs = sorted([*programs, finding.program], key=lambda program: program.name)
    return {
        "finding": finding,
        "entry": entry,
        "programs": programs,
        "selected_program": finding.program_id if finding else program_id,
        "starter": STARTER_REPORT,
        "form_action": f"/findings/{finding.id}/edit" if finding else "/findings/new",
        "tag_options": tag_names(db),
        "max_tags": MAX_TAGS,
        "tag_max_length": TAG_MAX_LENGTH,
        "relation_entries": db.query(KnowledgeEntry)
        .filter(KnowledgeEntry.id != (entry.id if entry else ""))
        .order_by(KnowledgeEntry.title)
        .all(),
        "related_ids": entry.related_ids if entry else [],
        "shared_findings": [other for other in entry.findings if other.id != finding.id] if entry else [],
    }


@router.get("/findings/new", response_class=HTMLResponse)
def vulnerability_new_page(request: Request, program_id: str = "", db: Session = Depends(get_db)):
    return render(request, "vulnerability_form.html", "findings", **_editor_values(db, program_id=program_id))


@router.post("/findings/new")
async def vulnerability_create(
    request: Request,
    program_id: str = Form(...),
    report: ReportRecord = Depends(report_fields),
    submission: SubmissionRecord = Depends(submission_fields),
    bounty: BountyRecord = Depends(bounty_fields),
    csrf: str = Form(...),
    uploads: list[UploadFile] | None = File(None),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = await create_vulnerability(request, db, program_id, report, submission, bounty, uploads)
    return RedirectResponse(finding.url, status_code=303)


def _import_page(request: Request, db: Session, program_id: str = "", error: str = "", status_code: int = 200):
    return render(
        request,
        "findings_import.html",
        "findings",
        error=error,
        programs=_open_programs(db),
        selected_program=program_id,
        max_upload_bytes=request.app.state.settings.max_upload_bytes,
        status_code=status_code,
    )


@router.get("/findings/import", response_class=HTMLResponse)
def vulnerability_import_page(request: Request, program_id: str = "", db: Session = Depends(get_db)):
    return _import_page(request, db, program_id)


@router.post("/findings/import", response_class=HTMLResponse)
async def vulnerability_import(
    request: Request,
    program_id: str = Form(...),
    upload: UploadFile = File(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    open_program(db, program_id, "Archived programs cannot receive vulnerabilities")
    limit = request.app.state.settings.max_upload_bytes
    payload = bytearray()
    while chunk := await upload.read(64 * 1024):
        payload.extend(chunk)
        if len(payload) > limit:
            return _import_page(request, db, program_id, "The Markdown file exceeds the configured upload limit.", 413)
    try:
        imported = parse_markdown_upload(
            upload.filename or "", bytes(payload), bug_types=BUG_TYPES, severities=SEVERITIES
        )
    except MarkdownImportError as exc:
        return _import_page(request, db, program_id, str(exc), exc.status_code)
    finding = await import_report(request, db, imported, program_id)
    return RedirectResponse(f"{finding.url}/edit", status_code=303)


@router.get("/findings/unfiled", response_class=HTMLResponse)
def unfiled_page(request: Request, db: Session = Depends(get_db)):
    return render(
        request, "findings_unfiled.html", "findings", entries=unfiled_entries(db), programs=_open_programs(db)
    )


def _get_unfiled(db: Session, knowledge_id: str) -> KnowledgeEntry:
    """A report no program has; a report that is filed is reached through its vulnerability."""
    entry = get_knowledge(db, knowledge_id)
    if entry.findings:
        raise HTTPException(status_code=404)
    return entry


@router.post("/findings/unfiled/{knowledge_id}/file")
def unfiled_file(
    request: Request,
    knowledge_id: str,
    program_id: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = file_report(request, db, _get_unfiled(db, knowledge_id), program_id)
    return RedirectResponse(f"{finding.url}/edit", status_code=303)


@router.post("/findings/unfiled/{knowledge_id}/delete")
def unfiled_delete(request: Request, knowledge_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    delete_report(request, db, _get_unfiled(db, knowledge_id))
    return RedirectResponse("/findings/unfiled", status_code=303)


def _neighbours(db: Session, finding: Finding) -> tuple[str, str]:
    """Pages of the vulnerabilities before and after this one in its program, newest first."""
    ids = [
        row.id
        for row in db.query(Finding.id)
        .filter(Finding.program_id == finding.program_id)
        .order_by(Finding.updated_at.desc(), Finding.id)
    ]
    position = ids.index(finding.id)
    before = f"/findings/{ids[position - 1]}" if position else ""
    after = f"/findings/{ids[position + 1]}" if position + 1 < len(ids) else ""
    return before, after


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def vulnerability_page(request: Request, finding_id: str, db: Session = Depends(get_db)):
    finding = get_finding(db, finding_id)
    entry = get_knowledge(db, finding.knowledge_id)
    previous_url, next_url = _neighbours(db, finding)
    return render(
        request,
        "vulnerability.html",
        "findings",
        finding=finding,
        entry=entry,
        rendered=render_markdown(entry.markdown, evidence_types(db, entry.markdown)),
        report_roles=report_roles(entry.markdown),
        related_reports=[*related_entries(entry), *backlink_only_entries(db, entry)],
        rediscover=rediscovery_for_entry(db, entry),
        shared_findings=[other for other in entry.findings if other.id != finding.id],
        programs=_open_programs(db),
        previous_url=previous_url,
        next_url=next_url,
    )


@router.get("/findings/{finding_id}/edit", response_class=HTMLResponse)
def vulnerability_edit_page(request: Request, finding_id: str, db: Session = Depends(get_db)):
    finding = get_finding(db, finding_id)
    return render(request, "vulnerability_form.html", "findings", **_editor_values(db, finding))


@router.post("/findings/{finding_id}/edit")
async def vulnerability_edit(
    request: Request,
    finding_id: str,
    program_id: str = Form(...),
    report: ReportRecord = Depends(report_fields),
    submission: SubmissionRecord = Depends(submission_fields),
    bounty: BountyRecord = Depends(bounty_fields),
    csrf: str = Form(...),
    uploads: list[UploadFile] | None = File(None),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    await update_vulnerability(request, db, finding, program_id, report, submission, bounty, uploads)
    return RedirectResponse(finding.url, status_code=303)


@router.post("/findings/{finding_id}/status")
def vulnerability_status(
    request: Request,
    finding_id: str,
    status: str = Form(...),
    outcome: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    set_status(request, db, finding, status, outcome)
    return RedirectResponse(finding.url, status_code=303)


@router.post("/findings/{finding_id}/bounty")
def vulnerability_bounty(
    request: Request,
    finding_id: str,
    payout: str = Form(""),
    bonus: str = Form(""),
    currency: str = Form(""),
    is_paid: list[str] | None = Form(None),
    return_to: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    record_bounty(request, db, finding, payout, bonus, currency, bool(checkbox(is_paid)))
    return RedirectResponse(local_path(return_to, finding.url), status_code=303)


@router.post("/findings/{finding_id}/paid")
def vulnerability_paid(
    request: Request,
    finding_id: str,
    paid: str = Form("1"),
    return_to: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    """Mark the reward of a submission as received (dated today) or as still owed."""
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    set_paid(request, db, finding, paid == "1")
    return RedirectResponse(local_path(return_to, finding.url), status_code=303)


@router.post("/findings/{finding_id}/evidence")
async def vulnerability_evidence(
    request: Request,
    finding_id: str,
    uploads: list[UploadFile] | None = File(None),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    await store_evidence_files(request, db, finding.knowledge, uploads)
    db.commit()
    return RedirectResponse(f"{finding.url}#attachments", status_code=303)


@router.post("/findings/{finding_id}/duplicate")
def vulnerability_duplicate(
    request: Request,
    finding_id: str,
    program_id: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    duplicate = duplicate_vulnerability(request, db, get_finding(db, finding_id), program_id)
    return RedirectResponse(f"{duplicate.url}/edit", status_code=303)


@router.post("/findings/{finding_id}/delete")
def vulnerability_delete(request: Request, finding_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    program_id = finding.program_id
    delete_vulnerability(request, db, finding)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@router.get("/findings/{finding_id}/markdown")
def vulnerability_download(request: Request, finding_id: str, db: Session = Depends(get_db)):
    entry = get_finding(db, finding_id).knowledge
    refresh_markdown(request, db, entry)
    return FileResponse(
        markdown_path(request.app.state.settings.markdown_dir, entry),
        media_type="text/markdown; charset=utf-8",
        filename=f"{entry.slug}.md",
    )
