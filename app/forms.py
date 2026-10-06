"""Parsing and validation of submitted form values."""

import math
from dataclasses import dataclass
from datetime import date

from fastapi import Form, HTTPException
from sqlalchemy.orm import Session

from .models import Finding, Program
from .taxonomy import BUG_TYPES, CURRENCIES, DEFAULT_CURRENCY, SEVERITIES


def lf(value: str) -> str:
    """Browsers submit textarea text with CRLF line breaks; store LF."""
    return value.replace("\r\n", "\n").replace("\r", "\n")


def checkbox(values: list[str] | None) -> bool | None:
    """Checkbox posted with a hidden ``0`` fallback: True/False, or None when the field is absent."""
    return None if values is None else "1" in values


def required_text(value: str, label: str, max_length: int) -> str:
    clean = value.strip()
    if not clean:
        raise HTTPException(status_code=422, detail=f"{label} is required")
    if len(clean) > max_length:
        raise HTTPException(status_code=422, detail=f"{label} must be {max_length} characters or fewer")
    return clean


def program_name(db: Session, value: str, exclude_id: str | None = None) -> str:
    """A unique program name. Case is folded in Python because SQLite lower() folds ASCII only."""
    name = required_text(value, "Program name", 180)
    folded = name.casefold()
    query = db.query(Program.id, Program.name)
    if exclude_id:
        query = query.filter(Program.id != exclude_id)
    if any(existing.casefold() == folded for _id, existing in query):
        raise HTTPException(status_code=409, detail="A program with this name already exists")
    return name


def entry_title(title: str, bug_type: str, severity: str) -> str:
    """Title of a knowledge entry, checked together with its bug type and severity."""
    clean = required_text(title, "Vulnerability title", 240)
    if bug_type not in BUG_TYPES or severity not in SEVERITIES:
        raise HTTPException(status_code=422)
    return clean


def entry_text(
    *,
    summary: str,
    endpoint: str,
    technology: str,
    cwe: str,
    cvss_score: str,
    research_notes: str,
    markdown: str,
    remediation: str,
    references: str,
) -> dict:
    """Free-text fields of a knowledge entry as they are stored."""
    return {
        "summary": lf(summary.strip()),
        "endpoint": endpoint.strip(),
        "technology": technology.strip(),
        "cwe": cwe.strip().upper(),
        "cvss_score": optional_cvss(cvss_score),
        "research_notes": lf(research_notes),
        "markdown": lf(markdown),
        "remediation": lf(remediation.strip()),
        "references": lf(references.strip()),
    }


def ensure_unlinked(db: Session, program_id: str, knowledge_id: str, finding_id: str = "") -> None:
    """A knowledge entry is linked to a program at most once."""
    query = db.query(Finding.id).filter(Finding.program_id == program_id, Finding.knowledge_id == knowledge_id)
    if finding_id:
        query = query.filter(Finding.id != finding_id)
    if query.first():
        raise HTTPException(status_code=409, detail="This knowledge is already linked to that program")


def optional_float(value: str, field: str = "Amount") -> float | None:
    if not value.strip():
        return None
    try:
        amount = float(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{field} must be a number") from None
    if not math.isfinite(amount) or amount < 0:
        raise HTTPException(status_code=422, detail=f"{field} must be zero or greater")
    return amount


def optional_cvss(value: str) -> float | None:
    if not value.strip():
        return None
    try:
        score = float(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="CVSS score must be a number") from None
    if not 0 <= score <= 10:
        raise HTTPException(status_code=422, detail="CVSS score must be between 0 and 10")
    return score


def optional_date(value: str, field: str) -> str:
    """Validate a browser date value and return canonical ISO form."""
    clean = value.strip()
    if not clean:
        return ""
    try:
        return date.fromisoformat(clean).isoformat()
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{field} must be a valid YYYY-MM-DD date") from None


@dataclass(frozen=True)
class BountyRecord:
    """Bounty fields of a finding, validated once for the create and edit routes."""

    triaged_at: str
    resolved_at: str
    rewarded_at: str
    payout: float | None
    bonus: float | None
    currency: str
    program_severity: str
    duplicate_of: str


def build_bounty(
    triaged_at: str,
    resolved_at: str,
    rewarded_at: str,
    payout: str,
    bonus: str,
    currency: str,
    program_severity: str,
    duplicate_of: str,
) -> BountyRecord:
    clean_currency = currency.strip().upper() or DEFAULT_CURRENCY
    if clean_currency not in CURRENCIES:
        raise HTTPException(status_code=422, detail="Unsupported currency")
    clean_program_severity = program_severity.strip().lower()
    if clean_program_severity and clean_program_severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid program severity")
    return BountyRecord(
        triaged_at=optional_date(triaged_at, "Triaged date"),
        resolved_at=optional_date(resolved_at, "Resolved date"),
        rewarded_at=optional_date(rewarded_at, "Rewarded date"),
        payout=optional_float(payout, "Payout"),
        bonus=optional_float(bonus, "Bonus"),
        currency=clean_currency,
        program_severity=clean_program_severity,
        duplicate_of=duplicate_of.strip(),
    )


def bounty_fields(
    triaged_at: str = Form(""),
    resolved_at: str = Form(""),
    rewarded_at: str = Form(""),
    payout: str = Form(""),
    bonus: str = Form(""),
    currency: str = Form(DEFAULT_CURRENCY),
    program_severity: str = Form(""),
    duplicate_of: str = Form(""),
) -> BountyRecord:
    """Bounty fields as named on the finding form."""
    return build_bounty(triaged_at, resolved_at, rewarded_at, payout, bonus, currency, program_severity, duplicate_of)


def apply_bounty(finding: Finding, bounty: BountyRecord) -> None:
    finding.triaged_at = bounty.triaged_at
    finding.resolved_at = bounty.resolved_at
    finding.rewarded_at = bounty.rewarded_at
    finding.payout = bounty.payout
    finding.bonus = bounty.bonus
    finding.currency = bounty.currency
    finding.program_severity = bounty.program_severity
    finding.duplicate_of = bounty.duplicate_of


def finding_dates(discovered_at: str, submitted_at: str, bounty: BountyRecord) -> tuple[str, str]:
    """Validate the discovery, submission and response dates of a finding."""
    discovered = optional_date(discovered_at, "Discovered date")
    submitted = optional_date(submitted_at, "Submitted date")
    if discovered and submitted and submitted < discovered:
        raise HTTPException(status_code=422, detail="Submitted date cannot be before discovered date")
    if submitted:
        for label, value in (
            ("Triaged date", bounty.triaged_at),
            ("Resolved date", bounty.resolved_at),
            ("Rewarded date", bounty.rewarded_at),
        ):
            if value and value < submitted:
                raise HTTPException(status_code=422, detail=f"{label} cannot be before submitted date")
    return discovered, submitted
