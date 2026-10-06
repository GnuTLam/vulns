"""Export for AI: the overview page, the JSON and Markdown downloads, and a per-entry preview."""

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from ..export import entry_document, export_json, export_markdown_zip, redaction_context
from ..models import KnowledgeEntry
from ..web import get_db, get_knowledge, render, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/knowledge/export", response_class=HTMLResponse)
def knowledge_export_page(request: Request, db: Session = Depends(get_db)):
    entries = db.query(KnowledgeEntry).order_by(KnowledgeEntry.title).all()
    return render(
        request,
        "export.html",
        "knowledge",
        included=[entry for entry in entries if entry.in_ai_export],
        excluded=[entry for entry in entries if not entry.use_for_ai],
        drafts=[entry for entry in entries if entry.use_for_ai and entry.is_draft],
    )


@router.get("/knowledge/export.json")
def knowledge_export_json(db: Session = Depends(get_db)):
    return Response(
        export_json(db),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulns-ai-export.json"'},
    )


@router.get("/knowledge/export.zip")
def knowledge_export_zip(db: Session = Depends(get_db)):
    return Response(
        export_markdown_zip(db),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="vulns-ai-export.zip"'},
    )


@router.get("/knowledge/{knowledge_id}/ai.json")
def knowledge_ai_preview(knowledge_id: str, db: Session = Depends(get_db)):
    """The redacted document this entry contributes to the AI export."""
    item = get_knowledge(db, knowledge_id)
    document = {"included": item.in_ai_export, **entry_document(item, redaction_context(db))}
    return Response(json.dumps(document, ensure_ascii=False, indent=2), media_type="application/json; charset=utf-8")
