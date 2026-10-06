"""The dashboard."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..stats import workspace_snapshot
from ..web import get_db, render, require_auth
from .search import SAVED_FILTERS

router = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    snapshot = workspace_snapshot(db)
    return render(
        request,
        "dashboard.html",
        "dashboard",
        **snapshot,
        max_status=max(snapshot["status_counts"].values(), default=1),
        max_severity=max(snapshot["severity_counts"].values(), default=1),
        saved_filter_queries=dict(SAVED_FILTERS),
        # An empty workspace shows a single getting-started panel.
        is_new_workspace=not snapshot["finding_total"] and not snapshot["knowledge_count"],
    )
