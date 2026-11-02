"""Earnings: rewards received and still owed, per currency."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..stats import earnings_report
from ..web import get_db, render, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/earnings", response_class=HTMLResponse)
def earnings(request: Request, year: str = "", currency: str = "", db: Session = Depends(get_db)):
    """``year`` is a four-digit year or ``all``; without one the latest year with rewards is shown."""
    report = earnings_report(db, year.strip(), currency.strip().upper())
    return render(request, "earnings.html", "earnings", **report)
