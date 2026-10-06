"""The search page and the JSON results behind the Ctrl+K palette."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from ..i18n import TRANSLATIONS, term
from ..search import HAS_VALUES, IS_VALUES, KINDS, compose_query, describe, parse_query, plain_snippet, run_search
from ..web import get_db, render, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])

# Preset lookups, written in the query language so they double as syntax examples.
SAVED_FILTERS = (
    ("needs_triage", "is:draft"),
    ("awaiting_response", "is:open -status:draft -status:not_submitted"),
    ("unpaid_accepted", "status:accepted -has:reward"),
    ("downgraded", "is:downgraded"),
)


def _palette_meta(item: dict) -> str:
    """Context line shown on the right of a palette row."""
    if item["kind"] == "knowledge":
        parts = [term(item.get("severity")), item.get("bug_type") or ""]
        if item.get("programs"):
            parts.append(" / ".join(item["programs"][:2]))
    elif item["kind"] == "finding":
        parts = [item.get("program") or "", term(item.get("status")), item.get("target") or ""]
    else:
        parts = [item.get("platform") or "", f"{item.get('finding_count', 0)} {TRANSLATIONS['findings'].casefold()}"]
    return " · ".join(part for part in parts if part)


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "", kind: str = "", db: Session = Depends(get_db)):
    """Search across research, program reports and programs."""
    selected_kind = kind if kind in KINDS else ""
    parsed = parse_query(compose_query(q, kind=selected_kind))
    results = (
        run_search(db, parsed, limit=40)
        if not parsed.is_empty
        else {
            "knowledge": [],
            "knowledge_total": 0,
            "findings": [],
            "findings_total": 0,
            "programs": [],
            "programs_total": 0,
            "total": 0,
        }
    )
    return render(
        request,
        "search.html",
        "search",
        q=q,
        selected_kind=selected_kind,
        chips=describe(parsed),
        warnings=parsed.warnings,
        results=results,
        searched=not parsed.is_empty,
        saved_filters=SAVED_FILTERS,
        is_values=IS_VALUES,
        has_values=HAS_VALUES,
    )


@router.get("/api/search")
def search_api(q: str = "", limit: int = 6, db: Session = Depends(get_db)):
    """JSON results for the Ctrl+K palette, grouped by kind."""
    parsed = parse_query(q)
    if parsed.is_empty:
        return JSONResponse({"query": q, "groups": [], "total": 0, "warnings": []})
    results = run_search(db, parsed, limit=max(1, min(limit, 15)))
    groups = [
        {
            "kind": kind,
            "label": TRANSLATIONS[key],
            "total": results[f"{key}_total"],
            "items": [
                {
                    "id": item["id"],
                    "title": item["title"],
                    "url": item["url"],
                    "meta": _palette_meta(item),
                    "snippet": plain_snippet(item.get("snippet")),
                }
                for item in results[key]
            ],
        }
        for kind, key in (("knowledge", "knowledge"), ("finding", "findings"), ("program", "programs"))
        if results[key]
    ]
    return JSONResponse({"query": q, "groups": groups, "total": results["total"], "warnings": parsed.warnings})
