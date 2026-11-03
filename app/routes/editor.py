"""Endpoints behind the vulnerability editor: the Markdown preview and related-report suggestions."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..database import candidate_related_ids
from ..security import validate_csrf
from ..taxonomy import parse_tags
from ..web import evidence_types, get_db, render_markdown, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


@router.post("/markdown/preview", response_class=HTMLResponse)
def markdown_preview(request: Request, markdown: str = Form(""), csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    return HTMLResponse(render_markdown(markdown, evidence_types(db, markdown)))


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
