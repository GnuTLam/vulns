"""Bounty programs."""

from collections import Counter

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session, selectinload

from ..database import push_rediscovery_for_signals
from ..forms import lf, program_name
from ..models import Program
from ..security import validate_csrf, validate_external_url
from ..stats import response_metrics, rewards_by_currency
from ..web import explorer_values, get_db, get_knowledge, get_program, refresh_markdown, render, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


def rediscovery_for_program(db: Session, program: Program) -> list[dict]:
    """Prior research related to a program's findings that is not linked to the program yet."""
    # Most recently updated first, so the eight titles used for text similarity are the current ones.
    linked = sorted(
        {finding.knowledge for finding in program.findings if finding.knowledge},
        key=lambda entry: (entry.updated_at, entry.id),
        reverse=True,
    )
    if not linked:
        return []
    cwe_counts: Counter[str] = Counter()
    bug_counts: Counter[str] = Counter()
    tech_counts: Counter[str] = Counter()
    tag_counter: Counter[str] = Counter()
    for entry in linked:
        if entry.cwe:
            cwe_counts[entry.cwe.strip().upper()] += 1
        if entry.bug_type:
            bug_counts[entry.bug_type] += 1
        if entry.technology:
            tech_counts[entry.technology] += 1
        tag_counter.update(entry.tag_names)
    return push_rediscovery_for_signals(
        db,
        cwe=cwe_counts.most_common(1)[0][0] if cwe_counts else "",
        bug_type=bug_counts.most_common(1)[0][0] if bug_counts else "",
        technology=", ".join(tech for tech, _ in tech_counts.most_common(3)),
        title=" ".join(entry.title for entry in linked[:8]),
        summary=program.notes or "",
        tags=[name for name, _count in tag_counter.most_common(5)],
        limit=6,
        exclude_ids={entry.id for entry in linked},
    )


@router.get("/programs", response_class=HTMLResponse)
def programs(request: Request, db: Session = Depends(get_db)):
    items = db.query(Program).options(selectinload(Program.findings)).order_by(Program.archived, Program.name).all()
    return render(request, "programs.html", "programs", programs=items, **explorer_values(db))


@router.get("/programs/new", response_class=HTMLResponse)
def program_new_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "program_form.html", "programs", program=None, **explorer_values(db))


@router.post("/programs/new")
def program_create(
    request: Request,
    name: str = Form(...),
    platform: str = Form(""),
    url: str = Form(""),
    handle: str = Form(""),
    notes: str = Form(""),
    archived: bool = Form(False),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    item = Program(
        name=program_name(db, name),
        platform=platform.strip(),
        url=validate_external_url(url, "Program URL"),
        handle=handle.strip(),
        notes=lf(notes),
        archived=archived,
    )
    db.add(item)
    db.commit()
    return RedirectResponse(f"/programs/{item.id}", status_code=303)


@router.get("/programs/{program_id}", response_class=HTMLResponse)
def program_detail(request: Request, program_id: str, db: Session = Depends(get_db)):
    item = get_program(db, program_id, with_findings=True)
    return render(
        request,
        "program_detail.html",
        "programs",
        program=item,
        rediscover=rediscovery_for_program(db, item),
        earnings=rewards_by_currency(item.findings),
        metrics=response_metrics(item.findings),
        **explorer_values(db, current_program_id=item.id),
    )


@router.get("/programs/{program_id}/edit", response_class=HTMLResponse)
def program_edit_page(request: Request, program_id: str, db: Session = Depends(get_db)):
    return render(
        request,
        "program_form.html",
        "programs",
        program=get_program(db, program_id),
        **explorer_values(db, current_program_id=program_id),
    )


@router.post("/programs/{program_id}/edit")
def program_edit(
    request: Request,
    program_id: str,
    name: str = Form(...),
    platform: str = Form(""),
    url: str = Form(""),
    handle: str = Form(""),
    notes: str = Form(""),
    archived: bool = Form(False),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    item = get_program(db, program_id)
    item.name = program_name(db, name, exclude_id=item.id)
    item.platform, item.url = platform.strip(), validate_external_url(url, "Program URL")
    item.handle, item.notes, item.archived = handle.strip(), lf(notes), archived
    db.commit()
    # Program names appear in the Markdown of every linked entry.
    refresh_markdown(request, db, *(finding.knowledge for finding in item.findings))
    return RedirectResponse(f"/programs/{item.id}", status_code=303)


def _set_archived(request: Request, program_id: str, csrf: str, db: Session, archived: bool) -> RedirectResponse:
    validate_csrf(request, csrf)
    item = get_program(db, program_id)
    item.archived = archived
    db.commit()
    return RedirectResponse(f"/programs/{item.id}", status_code=303)


@router.post("/programs/{program_id}/archive")
def program_archive(request: Request, program_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    return _set_archived(request, program_id, csrf, db, archived=True)


@router.post("/programs/{program_id}/restore")
def program_restore(request: Request, program_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    return _set_archived(request, program_id, csrf, db, archived=False)


@router.post("/programs/{program_id}/delete")
def program_delete(request: Request, program_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    item = get_program(db, program_id, with_findings=True)
    affected_ids = list(dict.fromkeys(finding.knowledge_id for finding in item.findings))
    db.delete(item)
    db.commit()
    # Only the program's findings are deleted. Knowledge and evidence stay, so refresh their Markdown.
    db.expire_all()
    refresh_markdown(request, db, *(get_knowledge(db, knowledge_id) for knowledge_id in affected_ids))
    return RedirectResponse("/knowledge?q=is%3Aorphan", status_code=303)
