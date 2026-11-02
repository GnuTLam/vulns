"""Figures shown on the dashboard, program and earnings pages, and returned by the agent overview."""

from collections import Counter
from datetime import date

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, selectinload

from .models import Finding, KnowledgeEntry, Program, day_gap
from .taxonomy import CLOSED_STATUSES, CURRENCIES, DEFAULT_CURRENCY, SEVERITIES

ATTENTION_ROWS = 6


def rewards_by_currency(findings) -> list[tuple[str, float]]:
    """Total reward per currency, largest first. Currencies are never added together."""
    totals: dict[str, float] = {}
    for finding in findings:
        amount = finding.total_reward
        if amount:
            currency = finding.currency or DEFAULT_CURRENCY
            totals[currency] = totals.get(currency, 0.0) + amount
    return sorted(totals.items(), key=lambda item: -item[1])


def _currency_order(code: str) -> tuple[int, str]:
    """Offered currencies first, in their listed order; legacy codes after, alphabetically."""
    return (CURRENCIES.index(code), "") if code in CURRENCIES else (len(CURRENCIES), code)


def earnings_by_currency(findings) -> list[dict]:
    """Paid and still-owed rewards per currency. Currencies are never added together."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.total_reward is not None:
            groups.setdefault(finding.currency or DEFAULT_CURRENCY, []).append(finding)
    rows = []
    for code in sorted(groups, key=_currency_order):
        items = groups[code]
        amounts = [finding.total_reward for finding in items]
        paid = [finding.total_reward for finding in items if finding.is_paid]
        rows.append(
            {
                "currency": code,
                "total": sum(amounts),
                "paid": sum(paid),
                "unpaid": sum(amounts) - sum(paid),
                "count": len(items),
                "paid_count": len(paid),
                "unpaid_count": len(items) - len(paid),
                "average": sum(amounts) / len(items),
                "largest": max(amounts),
            }
        )
    return rows


def response_metrics(findings) -> dict:
    """Median days to triage and to reward; the median keeps one stale report from skewing it."""
    triage = sorted(x for x in (f.days_to_triage for f in findings) if x is not None)
    reward = sorted(x for x in (f.days_to_reward for f in findings) if x is not None)

    def median(values: list[int]) -> int | None:
        if not values:
            return None
        middle = len(values) // 2
        if len(values) % 2:
            return values[middle]
        return round((values[middle - 1] + values[middle]) / 2)

    return {
        "median_triage_days": median(triage),
        "median_reward_days": median(reward),
        "rewarded_count": sum(1 for f in findings if f.total_reward is not None),
        "downgraded_count": sum(1 for f in findings if f.severity_delta < 0),
    }


def draft_count(db: Session) -> int:
    return db.query(func.count(KnowledgeEntry.id)).filter(KnowledgeEntry.is_draft.is_(True)).scalar() or 0


def workspace_snapshot(db: Session) -> dict:
    """Dashboard figures, shared by the dashboard page and the agent ``get_overview`` tool."""
    program_count = db.query(func.count(Program.id)).filter(Program.archived.is_(False)).scalar() or 0
    knowledge_count = db.query(func.count(KnowledgeEntry.id)).scalar() or 0
    all_findings = (
        db.query(Finding)
        .options(selectinload(Finding.program), selectinload(Finding.knowledge))
        .order_by(Finding.updated_at.desc())
        .all()
    )
    drafts_total = draft_count(db)

    # Oldest first. Each group shows a few rows but reports its full count.
    awaiting_all = sorted(
        (f for f in all_findings if f.status not in CLOSED_STATUSES),
        key=lambda f: (f.days_waiting is None, -(f.days_waiting or 0)),
    )
    unpaid_all = sorted(
        (f for f in all_findings if f.outcome == "accepted" and not f.is_paid),
        key=lambda f: (f.days_awaiting_reward is None, -(f.days_awaiting_reward or 0)),
    )
    awaiting, unpaid = awaiting_all[:ATTENTION_ROWS], unpaid_all[:ATTENTION_ROWS]
    drafts = (
        db.query(KnowledgeEntry)
        .filter(KnowledgeEntry.is_draft.is_(True))
        .order_by(KnowledgeEntry.updated_at.desc())
        .limit(ATTENTION_ROWS)
        .all()
    )
    attention_groups = {"awaiting": len(awaiting_all), "unpaid": len(unpaid_all), "drafts": drafts_total}
    shown_ids = {finding.id for finding in [*awaiting, *unpaid]}
    return {
        "program_count": program_count,
        "knowledge_count": knowledge_count,
        "finding_total": len(all_findings),
        "draft_count": drafts_total,
        # Matches the `is:open` search the dashboard card links to.
        "open_count": sum(1 for f in all_findings if f.status not in CLOSED_STATUSES),
        "accepted_count": sum(1 for f in all_findings if f.outcome == "accepted"),
        "status_counts": Counter(f.status for f in all_findings),
        "severity_counts": Counter(f.severity for f in all_findings),
        "earnings": rewards_by_currency(all_findings),
        "earnings_split": earnings_by_currency(all_findings),
        "metrics": response_metrics(all_findings),
        "awaiting": awaiting,
        "unpaid": unpaid,
        "drafts": drafts,
        "attention_groups": attention_groups,
        "attention_total": sum(attention_groups.values()),
        "recent_findings": [f for f in all_findings if f.id not in shown_ids][:ATTENTION_ROWS],
    }


def _bucket(rows: dict[str, dict], key: str, finding: Finding) -> None:
    row = rows.setdefault(key, {"paid": 0.0, "unpaid": 0.0, "count": 0})
    row["paid" if finding.is_paid else "unpaid"] += finding.total_reward
    row["count"] += 1


def earnings_report(db: Session, period: str = "", currency: str = "") -> dict:
    """The earnings page: paid and owed rewards per currency, by period, program and severity.

    ``period`` is a four-digit year, ``all``, or empty for the latest year with rewards. A
    reward counts towards the period of ``Finding.earned_on``. Money still owed is listed
    whatever the period, since it is outstanding either way.
    """
    rewarded = [
        finding
        for finding in db.query(Finding)
        .options(selectinload(Finding.program), selectinload(Finding.knowledge))
        .filter(or_(Finding.payout.isnot(None), Finding.bonus.isnot(None)))
        .all()
        if finding.total_reward is not None
    ]
    years = sorted({int(f.earned_on[:4]) for f in rewarded if f.earned_on[:4].isdigit()}, reverse=True)
    if period.isdigit() and len(period) == 4:
        year: int | None = int(period)
    else:
        year = years[0] if years and period != "all" else None
    in_period = [f for f in rewarded if year is None or f.earned_on.startswith(f"{year:04d}-")]
    summary = earnings_by_currency(in_period)
    codes = [row["currency"] for row in summary]
    selected = currency if currency in codes else (codes[0] if codes else "")
    chosen = [f for f in in_period if (f.currency or DEFAULT_CURRENCY) == selected]

    # Months of the chosen year, or one bar per year for all time.
    if year is None:
        labels = [str(item) for item in sorted(years)]
        timeline = {label: {"paid": 0.0, "unpaid": 0.0, "count": 0} for label in labels}
        for finding in chosen:
            _bucket(timeline, finding.earned_on[:4], finding)
    else:
        labels = [f"{year:04d}-{month:02d}" for month in range(1, 13)]
        timeline = {label: {"paid": 0.0, "unpaid": 0.0, "count": 0} for label in labels}
        for finding in chosen:
            _bucket(timeline, finding.earned_on[:7], finding)
    periods = [{"label": label, **timeline[label]} for label in labels if label in timeline]
    peak = max((row["paid"] + row["unpaid"] for row in periods), default=0.0)

    programs: dict[str, dict] = {}
    for finding in chosen:
        _bucket(programs, finding.program.name if finding.program else "", finding)
    by_program = sorted(
        ({"name": name, **row} for name, row in programs.items()),
        key=lambda row: -(row["paid"] + row["unpaid"]),
    )
    severities: dict[str, dict] = {}
    for finding in chosen:
        _bucket(severities, finding.effective_severity, finding)
    by_severity = [{"severity": name, **severities[name]} for name in reversed(SEVERITIES) if name in severities]

    unpaid = sorted(
        (f for f in rewarded if not f.is_paid),
        key=lambda f: f.rewarded_at or f.earned_on or "9999",
    )
    today = date.today().isoformat()
    return {
        "years": years,
        "selected_year": year,
        "summary": summary,
        "selected_currency": selected,
        "periods": periods,
        "peak": peak,
        "by_program": by_program,
        "by_severity": by_severity,
        "severity_peak": max((row["paid"] + row["unpaid"] for row in by_severity), default=0.0),
        "metrics": response_metrics(chosen),
        "unpaid": [(f, day_gap(f.rewarded_at or f.earned_on, today)) for f in unpaid],
        "unpaid_totals": earnings_by_currency(unpaid),
    }
