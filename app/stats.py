"""Figures shown on the dashboard, program pages and bounty tab, and returned by the agent overview."""

from calendar import month_name
from collections import Counter

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from .models import Finding, KnowledgeEntry, Program
from .taxonomy import CLOSED_STATUSES, CURRENCIES, DEFAULT_CURRENCY

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


def owed_summary(findings) -> dict:
    """What the programs still owe, from ``Finding.is_owed``: amounts per currency, plus how many
    owed reports have no amount recorded yet. The dashboard and the bounty tab both show this."""
    owed = [finding for finding in findings if finding.is_owed]
    totals: dict[str, dict] = {}
    for finding in owed:
        if finding.total_reward is not None:
            row = totals.setdefault(finding.currency or DEFAULT_CURRENCY, {"amount": 0.0, "count": 0})
            row["amount"] += finding.total_reward
            row["count"] += 1
    return {
        "count": len(owed),
        "rows": [{"currency": code, **totals[code]} for code in sorted(totals, key=_currency_order)],
        "unrecorded": sum(1 for finding in owed if finding.total_reward is None),
    }


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


def unfiled_count(db: Session) -> int:
    """Reports no program has."""
    return db.query(func.count(KnowledgeEntry.id)).filter(~KnowledgeEntry.findings.any()).scalar() or 0


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

    # Longest wait first. Each group shows a few rows but reports its full count. A draft has
    # not been sent, so it waits on the hunter (Drafts to finish), not on the program.
    awaiting_all = sorted(
        (f for f in all_findings if f.status not in CLOSED_STATUSES and not f.knowledge.is_draft),
        key=lambda f: -f.reply_wait[0],
    )
    unpaid_all = sorted(
        (f for f in all_findings if f.is_owed),
        key=lambda f: -f.payment_wait[0],
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
    shown_ids.update(finding.id for entry in drafts for finding in entry.findings)
    return {
        "program_count": program_count,
        "knowledge_count": knowledge_count,
        "finding_total": len(all_findings),
        "draft_count": drafts_total,
        "unfiled_count": unfiled_count(db),
        # Matches the `is:open` search the dashboard card links to.
        "open_count": sum(1 for f in all_findings if f.status not in CLOSED_STATUSES and not f.knowledge.is_draft),
        "accepted_count": sum(1 for f in all_findings if f.outcome == "accepted"),
        "status_counts": Counter(f.status for f in all_findings),
        # The dashboard pipeline counts an unsent draft as a draft, whatever its status field says.
        "pipeline_counts": Counter("draft" if f.knowledge.is_draft else f.status for f in all_findings),
        "severity_counts": Counter(f.severity for f in all_findings),
        "earnings": rewards_by_currency(all_findings),
        "earnings_split": earnings_by_currency(all_findings),
        "owed": owed_summary(all_findings),
        "metrics": response_metrics(all_findings),
        "awaiting": awaiting,
        "unpaid": unpaid,
        "drafts": drafts,
        "attention_groups": attention_groups,
        "attention_total": sum(attention_groups.values()),
        "recent_findings": [f for f in all_findings if f.id not in shown_ids][:ATTENTION_ROWS],
    }


def program_counts(findings) -> dict[str, int]:
    """Vulnerabilities of a program: all, still open (not done) and accepted by the program."""
    return {
        "total": len(findings),
        # Same rule as the dashboard's Open figure: an unsent draft is not open at a program.
        "open": sum(1 for f in findings if f.status not in CLOSED_STATUSES and not f.knowledge.is_draft),
        "accepted": sum(1 for f in findings if f.outcome == "accepted"),
    }


def _money_cell(rows: dict[str, dict], code: str, finding: Finding) -> None:
    """Adds a reward to the received or owed side of one currency's cell."""
    cell = rows.setdefault(code, {"paid": 0.0, "unpaid": 0.0, "count": 0})
    cell["paid" if finding.is_paid else "unpaid"] += finding.total_reward
    cell["count"] += 1


def earnings_report(db: Session, period: str = "", program_id: str = "") -> dict:
    """The bounty tab: every currency side by side, never added together.

    ``period`` is a four-digit year; anything else means all time, which is what the dashboard
    counts, so the two pages agree by default. A reward counts towards the month of
    ``Finding.earned_on`` (the day it was awarded). ``program_id`` narrows every figure to one
    program. Money still owed is listed whatever the period, since it is outstanding either
    way, and includes accepted reports whose amount is not recorded yet.
    """
    findings = [
        finding
        for finding in db.query(Finding).options(selectinload(Finding.program), selectinload(Finding.knowledge)).all()
        if not finding.knowledge.is_draft and (not program_id or finding.program_id == program_id)
    ]
    rewarded = [finding for finding in findings if finding.total_reward is not None]
    years = sorted({int(f.earned_on[:4]) for f in rewarded if f.earned_on[:4].isdigit()}, reverse=True)
    year: int | None = int(period) if period.isdigit() and len(period) == 4 and int(period) in years else None
    in_period = [f for f in rewarded if year is None or f.earned_on.startswith(f"{year:04d}-")]
    summary = earnings_by_currency(in_period)
    currencies = [row["currency"] for row in summary]

    # The ledger, newest first, in months; each month carries its own total per currency.
    months: dict[str, dict] = {}
    for finding in sorted(in_period, key=lambda f: (f.earned_on, f.id), reverse=True):
        key = finding.earned_on[:7]
        name = f"{month_name[int(key[5:])]} {key[:4]}" if key[5:].isdigit() else key
        month = months.setdefault(key, {"key": key, "name": name, "totals": {}, "items": []})
        _money_cell(month["totals"], finding.currency or DEFAULT_CURRENCY, finding)
        month["items"].append(finding)

    programs: dict[str, dict] = {}
    for finding in in_period:
        row = programs.setdefault(
            finding.program_id, {"id": finding.program_id, "name": finding.program.name, "count": 0, "money": {}}
        )
        row["count"] += 1
        _money_cell(row["money"], finding.currency or DEFAULT_CURRENCY, finding)

    unpaid = sorted(
        (f for f in findings if f.is_owed),
        key=lambda f: (f.total_reward is None, f.rewarded_at or f.resolved_at or f.triaged_at or "9999"),
    )
    return {
        "any_rewards": bool(rewarded) or bool(unpaid),
        "years": years,
        "selected_year": year,
        "summary": summary,
        "currencies": currencies,
        "months": list(months.values()),
        "by_program": sorted(programs.values(), key=lambda row: (-row["count"], row["name"].casefold())),
        "unpaid": unpaid,
        "owed": owed_summary(unpaid),
    }
