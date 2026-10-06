"""Findings: one knowledge entry submitted to one program."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..forms import BountyRecord, apply_bounty, bounty_fields, ensure_unlinked, finding_dates, lf
from ..models import Finding, KnowledgeEntry, Program
from ..search import compose_query, finding_rows, parse_query
from ..security import validate_csrf, validate_external_url
from ..taxonomy import SEVERITIES, STATUSES
from ..web import (
    explorer_values,
    get_db,
    get_finding,
    get_knowledge,
    get_program,
    refresh_markdown,
    render,
    require_auth,
)

router = APIRouter(dependencies=[Depends(require_auth)])

SEVERITY_COLORS = {
    "critical": "var(--sev-critical)",
    "high": "var(--sev-high)",
    "medium": "var(--sev-medium)",
    "low": "var(--sev-low)",
    "informational": "var(--sev-informational)",
}


def _severity_chart(severity_counts: dict[str, int], total: int) -> str:
    """Conic-gradient stops for the severity donut, most severe first."""
    cursor = 0.0
    segments: list[str] = []
    if total:
        for severity in reversed(SEVERITIES):
            end = cursor + (severity_counts[severity] / total * 360)
            if end > cursor:
                segments.append(f"{SEVERITY_COLORS[severity]} {cursor:.2f}deg {end:.2f}deg")
            cursor = end
    return ", ".join(segments) or "var(--surface-3) 0deg 360deg"


def _check_values(status: str, severity: str) -> None:
    if status not in STATUSES or severity not in SEVERITIES:
        raise HTTPException(status_code=422)


def _open_program(db: Session, program_id: str, message: str) -> Program:
    """The program a finding is filed under; archived programs take no new findings."""
    program = get_program(db, program_id)
    if program.archived:
        raise HTTPException(status_code=422, detail=message)
    return program


@router.get("/findings", response_class=HTMLResponse)
def findings_list(
    request: Request,
    q: str = "",
    status: str = "",
    severity: str = "",
    program_id: str = "",
    db: Session = Depends(get_db),
):
    effective = compose_query(
        q,
        status=status if status in STATUSES else "",
        severity=severity if severity in SEVERITIES else "",
        program_id=program_id,
    )
    parsed = parse_query(effective)
    items, result_total, _ranked = finding_rows(db, parsed, limit=500)
    all_findings = db.query(Finding).all()
    severity_counts = {item: sum(1 for finding in all_findings if finding.severity == item) for item in SEVERITIES}
    finding_metrics = {
        "total": len(all_findings),
        "submitted": sum(1 for finding in all_findings if finding.status in {"submitted", "triaged"}),
        "accepted": sum(1 for finding in all_findings if finding.status in {"accepted", "resolved", "paid"}),
        "rewarded": sum(1 for finding in all_findings if finding.total_reward is not None),
    }
    return render(
        request,
        "findings.html",
        "findings",
        findings=items,
        programs=db.query(Program).order_by(Program.name).all(),
        q=q,
        selected_status=status,
        selected_severity=severity,
        selected_program=program_id,
        result_total=result_total,
        severity_counts=severity_counts,
        severity_chart=_severity_chart(severity_counts, len(all_findings)),
        finding_metrics=finding_metrics,
        query_warnings=parsed.warnings,
    )


@router.get("/findings/new", response_class=HTMLResponse)
def finding_new_page(
    request: Request,
    knowledge_id: str = "",
    program_id: str = "",
    db: Session = Depends(get_db),
):
    return render(
        request,
        "finding_form.html",
        "programs" if program_id else "findings",
        finding=None,
        programs=db.query(Program).filter(Program.archived.is_(False)).order_by(Program.name).all(),
        entries=db.query(KnowledgeEntry).order_by(KnowledgeEntry.title).all(),
        selected_knowledge=knowledge_id,
        selected_program=program_id,
        **(explorer_values(db, current_program_id=program_id, current_knowledge_id=knowledge_id) if program_id else {}),
    )


@router.post("/findings/new")
def finding_create(
    request: Request,
    program_id: str = Form(...),
    knowledge_id: str = Form(...),
    target: str = Form(""),
    scope: str = Form(""),
    status: str = Form(...),
    severity: str = Form(...),
    report_id: str = Form(""),
    report_url: str = Form(""),
    discovered_at: str = Form(""),
    submitted_at: str = Form(""),
    private_notes: str = Form(""),
    bounty: BountyRecord = Depends(bounty_fields),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    _open_program(db, program_id, "Archived programs cannot receive vulnerabilities")
    knowledge = get_knowledge(db, knowledge_id)
    ensure_unlinked(db, program_id, knowledge_id)
    _check_values(status, severity)
    discovered_at, submitted_at = finding_dates(discovered_at, submitted_at, bounty)
    item = Finding(
        program_id=program_id,
        knowledge_id=knowledge_id,
        target=target.strip(),
        scope=scope.strip(),
        status=status,
        severity=severity,
        report_id=report_id.strip(),
        report_url=validate_external_url(report_url, "Report URL"),
        discovered_at=discovered_at,
        submitted_at=submitted_at,
        private_notes=lf(private_notes),
    )
    apply_bounty(item, bounty)
    db.add(item)
    db.commit()
    db.refresh(knowledge)
    refresh_markdown(request, db, get_knowledge(db, knowledge_id))
    return RedirectResponse(item.url, status_code=303)


@router.get("/findings/{finding_id}/edit", response_class=HTMLResponse)
def finding_edit_page(request: Request, finding_id: str, db: Session = Depends(get_db)):
    item = get_finding(db, finding_id)
    return render(
        request,
        "finding_form.html",
        "programs",
        finding=item,
        programs=db.query(Program).order_by(Program.name).all(),
        entries=db.query(KnowledgeEntry).order_by(KnowledgeEntry.title).all(),
        selected_knowledge=item.knowledge_id,
        selected_program=item.program_id,
        **explorer_values(db, item.program_id, item.knowledge_id, item.id),
    )


@router.post("/findings/{finding_id}/move")
def finding_move(
    request: Request,
    finding_id: str,
    program_id: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    """Move a finding to another program without copying its knowledge."""
    validate_csrf(request, csrf)
    finding = get_finding(db, finding_id)
    destination = _open_program(db, program_id, "Cannot move a vulnerability to an archived program")
    if finding.program_id != destination.id:
        ensure_unlinked(db, destination.id, finding.knowledge_id, finding_id=finding.id)
        finding.program_id = destination.id
        db.commit()
        refresh_markdown(request, db, get_knowledge(db, finding.knowledge_id))
    return RedirectResponse(finding.url, status_code=303)


@router.post("/findings/{finding_id}/edit")
def finding_edit(
    request: Request,
    finding_id: str,
    program_id: str = Form(...),
    knowledge_id: str = Form(...),
    target: str = Form(""),
    scope: str = Form(""),
    status: str = Form(...),
    severity: str = Form(...),
    report_id: str = Form(""),
    report_url: str = Form(""),
    discovered_at: str = Form(""),
    submitted_at: str = Form(""),
    private_notes: str = Form(""),
    bounty: BountyRecord = Depends(bounty_fields),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    item = get_finding(db, finding_id)
    destination = get_program(db, program_id)
    # A finding may stay in a program archived after it was filed, but cannot move into one.
    if destination.archived and destination.id != item.program_id:
        raise HTTPException(status_code=422, detail="Cannot move a vulnerability to an archived program")
    get_knowledge(db, knowledge_id)
    ensure_unlinked(db, program_id, knowledge_id, finding_id=item.id)
    _check_values(status, severity)
    discovered_at, submitted_at = finding_dates(discovered_at, submitted_at, bounty)
    old_knowledge_id = item.knowledge_id
    item.program_id, item.knowledge_id = program_id, knowledge_id
    item.target, item.scope, item.status, item.severity = target.strip(), scope.strip(), status, severity
    item.report_id, item.report_url = report_id.strip(), validate_external_url(report_url, "Report URL")
    item.discovered_at, item.submitted_at = discovered_at, submitted_at
    item.private_notes = lf(private_notes)
    apply_bounty(item, bounty)
    db.commit()
    refresh_markdown(request, db, get_knowledge(db, old_knowledge_id))
    if old_knowledge_id != knowledge_id:
        refresh_markdown(request, db, get_knowledge(db, knowledge_id))
    return RedirectResponse(item.url, status_code=303)


@router.post("/findings/{finding_id}/delete")
def finding_delete(request: Request, finding_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    item = get_finding(db, finding_id)
    knowledge_id = item.knowledge_id
    db.delete(item)
    db.commit()
    refresh_markdown(request, db, get_knowledge(db, knowledge_id))
    return RedirectResponse(f"/knowledge/{knowledge_id}", status_code=303)
