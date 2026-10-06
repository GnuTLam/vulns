"""Tags: the tag manager page and the helpers that attach tags to entries."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import index_knowledge
from ..models import KnowledgeEntry, Tag, knowledge_tags
from ..security import validate_csrf
from ..taxonomy import TAG_MAX_LENGTH, normalize_tag, parse_tags
from ..web import get_db, refresh_markdown, render, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


def assign_tags(db: Session, entry: KnowledgeEntry, raw: str | list[str]) -> None:
    names = parse_tags(raw)
    existing = {tag.name: tag for tag in db.query(Tag).filter(Tag.name.in_(names))} if names else {}
    entry.tags = [existing.get(name) or Tag(name=name) for name in names]


def prune_tags(db: Session) -> None:
    """Delete tags no entry uses any more."""
    db.query(Tag).filter(~Tag.entries.any()).delete(synchronize_session=False)


def tag_names(db: Session) -> list[str]:
    return [name for (name,) in db.query(Tag.name).order_by(Tag.name)]


def tag_counts(db: Session) -> list[tuple[Tag, int]]:
    return (
        db.query(Tag, func.count(knowledge_tags.c.knowledge_id))
        .outerjoin(knowledge_tags, knowledge_tags.c.tag_id == Tag.id)
        .group_by(Tag.id)
        .order_by(Tag.name)
        .all()
    )


def _get_tag(db: Session, tag_id: int) -> Tag:
    tag = db.get(Tag, tag_id)
    if not tag:
        raise HTTPException(status_code=404)
    return tag


def _refresh(request: Request, db: Session, entries: list[KnowledgeEntry]) -> None:
    """Tags are part of the search index and of each entry's Markdown."""
    for entry in entries:
        index_knowledge(db, entry)
    db.commit()
    refresh_markdown(request, db, *entries)


@router.get("/knowledge/tags", response_class=HTMLResponse)
def tags_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "tags.html", "knowledge", tags=tag_counts(db), tag_max_length=TAG_MAX_LENGTH)


@router.post("/knowledge/tags/{tag_id}/rename")
def tag_rename(
    request: Request,
    tag_id: int,
    name: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    tag = _get_tag(db, tag_id)
    new_name = normalize_tag(name)
    if not new_name:
        raise HTTPException(status_code=422, detail="Tag name is required")
    affected = list(tag.entries)
    if new_name != tag.name:
        existing = db.query(Tag).filter(Tag.name == new_name).first()
        if existing:
            # Renaming onto an existing tag merges the two.
            for entry in affected:
                entry.tags.remove(tag)
                if existing not in entry.tags:
                    entry.tags.append(existing)
            db.delete(tag)
        else:
            tag.name = new_name
        _refresh(request, db, affected)
    return RedirectResponse("/knowledge/tags", status_code=303)


@router.post("/knowledge/tags/{tag_id}/delete")
def tag_delete(request: Request, tag_id: int, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    tag = _get_tag(db, tag_id)
    affected = list(tag.entries)
    for entry in affected:
        entry.tags.remove(tag)
    db.delete(tag)
    _refresh(request, db, affected)
    return RedirectResponse("/knowledge/tags", status_code=303)
