"""Figures shown on the dashboard and program pages, and returned by the agent overview."""

from collections import Counter

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from .models import Finding, KnowledgeEntry, Program
from .search import CLOSED_STATUSES
from .taxonomy import DEFAULT_CURRENCY

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
        (f for f in all_findings if f.status in {"submitted", "triaged"}),
        key=lambda f: (f.days_waiting is None, -(f.days_waiting or 0)),
    )
    unpaid_all = sorted(
        (f for f in all_findings if f.status == "accepted" and f.total_reward is None),
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
        "accepted_count": sum(1 for f in all_findings if f.status in {"accepted", "resolved", "paid"}),
        "status_counts": Counter(f.status for f in all_findings),
        "severity_counts": Counter(f.severity for f in all_findings),
        "earnings": rewards_by_currency(all_findings),
        "metrics": response_metrics(all_findings),
        "awaiting": awaiting,
        "unpaid": unpaid,
        "drafts": drafts,
        "attention_groups": attention_groups,
        "attention_total": sum(attention_groups.values()),
        "recent_findings": [f for f in all_findings if f.id not in shown_ids][:ATTENTION_ROWS],
    }
