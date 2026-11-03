"""Vulnerabilities: a report (knowledge entry) together with its submission to a program (finding).

The web routes and the agent API both save through these functions, so validation, Markdown
files and search indexing behave the same whichever way a record is changed. Each function
commits once and rewrites the Markdown files only after the commit.
"""

import shutil
import uuid
from dataclasses import replace
from datetime import date
from pathlib import Path

from fastapi import HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from .database import (
    backlink_entries,
    index_knowledge,
    push_rediscovery_for_entry,
    remove_knowledge_index,
)
from .forms import (
    BountyRecord,
    ReportRecord,
    SubmissionRecord,
    apply_bounty,
    build_bounty,
    build_report,
    build_submission,
    check_currency,
    current_bounty,
    ensure_unlinked,
    finding_dates,
)
from .markdown_import import ImportedMarkdown
from .markdown_store import delete_markdown, unique_slug
from .models import Evidence, Finding, KnowledgeEntry, Program, new_id
from .routes.evidence import store_evidence_files
from .routes.tags import assign_tags, prune_tags
from .taxonomy import DEFAULT_CURRENCY, OUTCOMES, STATUSES
from .web import EVIDENCE_REFERENCE, get_program, refresh_markdown, report_url

REPORT_TEXT_FIELDS = ("summary", "markdown", "remediation", "references", "research_notes")


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


def with_report_urls(db: Session, items: list[dict]) -> list[dict]:
    """Rediscovery candidates with the ``url`` of the page that shows each report."""
    entries = {
        entry.id: entry
        for entry in db.query(KnowledgeEntry).filter(KnowledgeEntry.id.in_([item["id"] for item in items]))
    }
    return [{**item, "url": report_url(entries[item["id"]])} for item in items if item["id"] in entries]


def rediscovery_for_entry(db: Session, entry: KnowledgeEntry) -> list[dict]:
    """Related prior research for an entry, excluding entries already linked either way."""
    known = set(entry.related_ids)
    known.update(item.id for item in backlink_entries(db, entry.id))
    return with_report_urls(db, push_rediscovery_for_entry(db, entry, limit=5, exclude_ids=known))


def unfiled_entries(db: Session) -> list[KnowledgeEntry]:
    """Reports no program has: old quick captures, imports and the reports of deleted programs."""
    return (
        db.query(KnowledgeEntry).filter(~KnowledgeEntry.findings.any()).order_by(KnowledgeEntry.updated_at.desc()).all()
    )


def is_shared(entry: KnowledgeEntry, finding: Finding) -> bool:
    """Whether another submission uses the report of this finding."""
    return any(other.id != finding.id for other in entry.findings)


def open_program(db: Session, program_id: str, message: str) -> Program:
    """The program a vulnerability is filed under; archived programs take no new ones."""
    program = get_program(db, program_id)
    if program.archived:
        raise HTTPException(status_code=422, detail=message)
    return program


# Reports


async def _save_report(
    request: Request,
    db: Session,
    entry: KnowledgeEntry,
    report: ReportRecord,
    uploads: list[UploadFile] | None,
    *,
    draft: bool,
) -> dict[str, KnowledgeEntry]:
    """Write a report onto its entry without committing.

    Returns the entries whose Markdown file must be rewritten after the commit: this one, and
    those it links to before or after the save, since their referenced-by lists change.
    """
    previously_related = list(entry.related)
    entry.title, entry.slug = report.title, unique_slug(db, report.title, current_id=entry.id)
    entry.bug_type, entry.default_severity = report.bug_type, report.severity
    for name, value in report.text.items():
        setattr(entry, name, value)
    entry.is_draft = draft
    if report.use_for_ai is not None:
        entry.use_for_ai = report.use_for_ai
    if report.tags is not None:
        assign_tags(db, entry, report.tags)
    entry.related = entries_by_id(db, report.related_ids, current_id=entry.id)
    await store_evidence_files(request, db, entry, uploads)
    index_knowledge(db, entry)
    prune_tags(db)
    return {item.id: item for item in [entry, *previously_related, *entry.related]}


def _new_entry(db: Session, report: ReportRecord) -> KnowledgeEntry:
    entry = KnowledgeEntry(
        title=report.title,
        slug=unique_slug(db, report.title),
        bug_type=report.bug_type,
        default_severity=report.severity,
    )
    db.add(entry)
    db.flush()
    return entry


async def create_report(
    request: Request,
    db: Session,
    report: ReportRecord,
    uploads: list[UploadFile] | None = None,
    *,
    draft: bool = False,
) -> KnowledgeEntry:
    """Save a report no program has yet; it is listed as unfiled until it is filed."""
    entry = _new_entry(db, report)
    linked = await _save_report(request, db, entry, report, uploads, draft=draft)
    db.commit()
    refresh_markdown(request, db, *linked.values())
    return entry


async def update_report(
    request: Request,
    db: Session,
    entry: KnowledgeEntry,
    report: ReportRecord,
    uploads: list[UploadFile] | None = None,
    *,
    draft: bool = False,
) -> None:
    """Replace the fields of a report. Saving completes triage, so ``draft`` is off unless asked for."""
    linked = await _save_report(request, db, entry, report, uploads, draft=draft)
    db.commit()
    refresh_markdown(request, db, *linked.values())


def delete_report(request: Request, db: Session, entry: KnowledgeEntry) -> None:
    """Delete a report with its submissions, evidence files and Markdown file."""
    settings = request.app.state.settings
    evidence_paths = [settings.evidence_dir / evidence.stored_name for evidence in entry.evidence]
    # Entries linked in either direction need their Markdown refreshed afterwards.
    affected = {item.id: item for item in [*entry.related, *backlink_entries(db, entry.id)]}
    remove_knowledge_index(db, entry.id)
    delete_markdown(settings.markdown_dir, entry)
    db.delete(entry)
    db.flush()
    prune_tags(db)
    db.commit()
    db.expire_all()
    # Remove files only after the commit succeeds.
    for path in evidence_paths:
        path.unlink(missing_ok=True)
    refresh_markdown(request, db, *affected.values())


# Submissions


def _fill_finding(finding: Finding, submission: SubmissionRecord, bounty: BountyRecord) -> None:
    """Validate the dates and write the submission and bounty fields onto a finding."""
    finding.discovered_at, finding.submitted_at = finding_dates(
        submission.discovered_at, submission.submitted_at, bounty
    )
    finding.target, finding.scope = submission.target, submission.scope
    finding.status, finding.outcome, finding.severity = submission.status, submission.outcome, submission.severity
    finding.report_id, finding.report_url = submission.report_id, submission.report_url
    finding.private_notes = submission.private_notes
    apply_bounty(finding, bounty)


def _new_finding(program_id: str, submission: SubmissionRecord, bounty: BountyRecord) -> Finding:
    check_currency(bounty)
    finding = Finding(program_id=program_id)
    _fill_finding(finding, submission, bounty)
    return finding


def _move_finding(
    db: Session,
    finding: Finding,
    entry: KnowledgeEntry,
    program_id: str,
    submission: SubmissionRecord,
    bounty: BountyRecord,
) -> None:
    """Validate and apply a full edit of a finding without committing; the report may change too."""
    destination = get_program(db, program_id)
    # A finding may stay in a program archived after it was filed, but cannot move into one.
    if destination.archived and destination.id != finding.program_id:
        raise HTTPException(status_code=422, detail="Cannot move a vulnerability to an archived program")
    ensure_unlinked(db, destination.id, entry.id, finding_id=finding.id)
    check_currency(bounty, finding.currency)
    _fill_finding(finding, submission, bounty)
    finding.program_id, finding.knowledge_id = destination.id, entry.id


def create_finding(
    request: Request,
    db: Session,
    entry: KnowledgeEntry,
    program_id: str,
    submission: SubmissionRecord,
    bounty: BountyRecord,
) -> Finding:
    """Submit an existing report to a program."""
    program = open_program(db, program_id, "Archived programs cannot receive vulnerabilities")
    ensure_unlinked(db, program.id, entry.id)
    finding = _new_finding(program.id, submission, bounty)
    finding.knowledge_id = entry.id
    db.add(finding)
    db.commit()
    refresh_markdown(request, db, entry)
    return finding


def update_finding(
    request: Request,
    db: Session,
    finding: Finding,
    entry: KnowledgeEntry,
    program_id: str,
    submission: SubmissionRecord,
    bounty: BountyRecord,
) -> None:
    """Change a submission, including the program and the report it points to."""
    previous = finding.knowledge
    _move_finding(db, finding, entry, program_id, submission, bounty)
    db.commit()
    refresh_markdown(request, db, previous)
    if previous.id != entry.id:
        refresh_markdown(request, db, entry)


def delete_finding(request: Request, db: Session, finding: Finding) -> None:
    """Unlink a report from its program; the report is kept, unfiled when no other program has it."""
    entry = finding.knowledge
    db.delete(finding)
    db.commit()
    refresh_markdown(request, db, entry)


def file_report(request: Request, db: Session, entry: KnowledgeEntry, program_id: str) -> Finding:
    """Submit an unfiled report to a program, rated as the report is."""
    program = open_program(db, program_id, "Archived programs cannot receive vulnerabilities")
    ensure_unlinked(db, program.id, entry.id)
    finding = Finding(program_id=program.id, knowledge_id=entry.id, status="submitted", severity=entry.default_severity)
    db.add(finding)
    db.commit()
    refresh_markdown(request, db, entry)
    return finding


# Vulnerabilities: report and submission in one transaction


async def create_vulnerability(
    request: Request,
    db: Session,
    program_id: str,
    report: ReportRecord,
    submission: SubmissionRecord,
    bounty: BountyRecord,
    uploads: list[UploadFile] | None = None,
    *,
    draft: bool = False,
) -> Finding:
    """Create a report and its submission to a program together."""
    program = open_program(db, program_id, "Archived programs cannot receive vulnerabilities")
    # Everything but the uploads is checked first, so a bad field leaves no files behind.
    finding = _new_finding(program.id, submission, bounty)
    entry = _new_entry(db, report)
    linked = await _save_report(request, db, entry, report, uploads, draft=draft)
    finding.knowledge_id = entry.id
    db.add(finding)
    db.commit()
    refresh_markdown(request, db, *linked.values())
    return finding


async def update_vulnerability(
    request: Request,
    db: Session,
    finding: Finding,
    program_id: str,
    report: ReportRecord,
    submission: SubmissionRecord,
    bounty: BountyRecord,
    uploads: list[UploadFile] | None = None,
) -> None:
    """Save report and submission of a vulnerability together; a changed program moves it."""
    entry = finding.knowledge
    shared = is_shared(entry, finding)
    _move_finding(db, finding, entry, program_id, submission, bounty)
    if shared:
        # The rating of a shared report stays what the other submissions were filed with.
        report = replace(report, severity=entry.default_severity)
    linked = await _save_report(request, db, entry, report, uploads, draft=False)
    db.commit()
    refresh_markdown(request, db, *linked.values())


def delete_vulnerability(request: Request, db: Session, finding: Finding) -> None:
    """Delete a submission together with its report, unless another program still uses the report."""
    entry = finding.knowledge
    if is_shared(entry, finding):
        delete_finding(request, db, finding)
    else:
        delete_report(request, db, entry)


def _retarget_evidence(text: str, renamed: dict[str, str]) -> str:
    """Point ``/evidence/<id>`` references at the copied files."""
    return EVIDENCE_REFERENCE.sub(lambda match: f"/evidence/{renamed.get(match.group(1), match.group(1))}", text)


def duplicate_vulnerability(request: Request, db: Session, finding: Finding, program_id: str) -> Finding:
    """Copy a report into a new vulnerability of a program, with its own evidence files.

    The copy starts as ``submitted`` with no report ID, dates or bounty.
    """
    program = open_program(db, program_id, "Cannot duplicate a vulnerability into an archived program")
    source = finding.knowledge
    settings = request.app.state.settings
    title = f"{source.title} (Copy)"[:240] if program.id == finding.program_id else source.title
    copy = KnowledgeEntry(
        title=title,
        slug=unique_slug(db, title),
        bug_type=source.bug_type,
        default_severity=finding.severity,
        endpoint=source.endpoint,
        technology=source.technology,
        cwe=source.cwe,
        cvss_score=source.cvss_score,
        use_for_ai=source.use_for_ai,
        **{name: getattr(source, name) for name in REPORT_TEXT_FIELDS},
    )
    db.add(copy)
    db.flush()
    copied: list[Path] = []
    renamed: dict[str, str] = {}
    try:
        for item in source.evidence:
            origin = settings.evidence_dir / item.stored_name
            if not origin.exists():
                continue
            stored_name = f"{uuid.uuid4()}{Path(item.stored_name).suffix}"
            copied.append(settings.evidence_dir / stored_name)
            shutil.copyfile(origin, copied[-1])
            renamed[item.id] = new_id()
            db.add(
                Evidence(
                    id=renamed[item.id],
                    knowledge_id=copy.id,
                    filename=item.filename,
                    stored_name=stored_name,
                    mime_type=item.mime_type,
                    size_bytes=item.size_bytes,
                )
            )
        for name in REPORT_TEXT_FIELDS:
            setattr(copy, name, _retarget_evidence(getattr(copy, name), renamed))
        copy.tags = list(source.tags)
        copy.related = list(source.related)
        duplicate = Finding(program_id=program.id, knowledge_id=copy.id, status="submitted", severity=finding.severity)
        db.add(duplicate)
        index_knowledge(db, copy)
        db.commit()
    except Exception:
        for path in copied:
            path.unlink(missing_ok=True)
        raise
    # The copy links to the entries the source links to; refresh their referenced-by lists.
    refresh_markdown(request, db, copy, *related_entries(copy))
    return duplicate


async def import_report(request: Request, db: Session, imported: ImportedMarkdown, program_id: str) -> Finding:
    """File an imported Markdown report to a program as a draft to review."""
    report = build_report(
        title=imported.title,
        bug_type=imported.bug_type,
        severity=imported.default_severity,
        summary=imported.summary,
        endpoint=imported.endpoint,
        technology=imported.technology,
        cwe=imported.cwe,
        cvss_score="" if imported.cvss_score is None else str(imported.cvss_score),
        research_notes=imported.research_notes,
        markdown=imported.markdown,
        remediation=imported.remediation,
        references=imported.references,
        tags=imported.tags,
        use_for_ai=imported.use_for_ai,
        related_ids=[],
    )
    submission = build_submission(severity=imported.default_severity)
    bounty = build_bounty("", "", "", "", "", DEFAULT_CURRENCY, "", "")
    return await create_vulnerability(request, db, program_id, report, submission, bounty, draft=True)


# Quick actions on one submission. Unlike the full form they date a change that happens today.


def set_status(request: Request, db: Session, finding: Finding, status: str, outcome: str) -> None:
    """Change status and outcome; the first triage and an accepted resolution are dated today."""
    if status not in STATUSES or outcome not in OUTCOMES:
        raise HTTPException(status_code=422)
    today = date.today().isoformat()
    bounty = current_bounty(finding)
    if status in ("processing", "done") and not bounty.triaged_at:
        bounty = replace(bounty, triaged_at=today)
    if status == "done" and outcome == "accepted" and not bounty.resolved_at:
        bounty = replace(bounty, resolved_at=today)
    finding_dates(finding.discovered_at, finding.submitted_at, bounty)
    finding.status, finding.outcome = status, outcome
    apply_bounty(finding, bounty)
    db.commit()
    refresh_markdown(request, db, finding.knowledge)


def record_bounty(
    request: Request, db: Session, finding: Finding, payout: str, bonus: str, currency: str, is_paid: bool
) -> None:
    """Record the reward; dates it today and accepts the report, unless those are already set."""
    today = date.today().isoformat()
    bounty = build_bounty(
        finding.triaged_at,
        finding.resolved_at,
        finding.rewarded_at,
        payout,
        bonus,
        currency,
        finding.program_severity,
        finding.duplicate_of,
        is_paid=is_paid,
        paid_at=finding.paid_at if is_paid else "",
    )
    check_currency(bounty, finding.currency)
    awarded = (bounty.payout or 0.0) + (bounty.bonus or 0.0) > 0
    if awarded and not bounty.rewarded_at:
        bounty = replace(bounty, rewarded_at=today)
    if bounty.is_paid and not bounty.paid_at:
        bounty = replace(bounty, paid_at=today)
    finding_dates(finding.discovered_at, finding.submitted_at, bounty)
    if awarded and not finding.outcome:
        finding.outcome = "accepted"
    apply_bounty(finding, bounty)
    db.commit()
    refresh_markdown(request, db, finding.knowledge)


def set_paid(request: Request, db: Session, finding: Finding, paid: bool) -> None:
    """Mark the reward as received (dated today) or as still owed."""
    finding.is_paid = paid
    finding.paid_at = (finding.paid_at or date.today().isoformat()) if paid else ""
    db.commit()
    refresh_markdown(request, db, finding.knowledge)
