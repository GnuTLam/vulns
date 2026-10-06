"""Lookup query language.

    oauth redirect      every word must match (prefix match)
    "open redirect"     exact phrase
    -csrf               exclude a word
    sev:critical        field filter; aliases such as severity: also work
    cvss:>=8            numeric comparison
    after:2026-01-01    bound on last update
    is:draft has:poc    predicates
    kind:program        restrict the entity kinds searched

Unknown fields come back as warnings and are searched as plain text.
"""

from __future__ import annotations

import html
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from markupsafe import Markup, escape
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session, selectinload

from .database import (
    HIGHLIGHT_CLOSE,
    HIGHLIGHT_OPEN,
    fts_entity_matches,
    fts_knowledge_matches,
)
from .models import Finding, KnowledgeEntry, Program, Tag
from .taxonomy import SEVERITIES, normalize_tag

KINDS = ("knowledge", "finding", "program")

# Canonical field name -> accepted aliases.
FIELD_ALIASES: dict[str, str] = {
    "severity": "severity",
    "sev": "severity",
    "status": "status",
    "state": "status",
    "type": "bug_type",
    "bug": "bug_type",
    "bugtype": "bug_type",
    "class": "bug_type",
    "cwe": "cwe",
    "tag": "tag",
    "tags": "tag",
    "label": "tag",
    "tech": "technology",
    "technology": "technology",
    "stack": "technology",
    "program": "program",
    "prog": "program",
    "target": "target",
    "program_id": "program_id",
    "programid": "program_id",
    "endpoint": "endpoint",
    "path": "endpoint",
    "url": "endpoint",
    "cvss": "cvss",
    "score": "cvss",
    "payout": "payout",
    "bounty": "payout",
    "reward": "payout",
    "currency": "currency",
    "cur": "currency",
    "after": "after",
    "since": "after",
    "before": "before",
    "until": "before",
    "is": "is",
    "has": "has",
    "kind": "kind",
    "in": "kind",
}

# Values accepted by `is:` and `has:`; anything else produces a warning.
IS_VALUES = (
    "draft",
    "linked",
    "orphan",
    "archived",
    "submitted",
    "paid",
    "accepted",
    "open",
    "rewarded",
    "downgraded",
    "duplicate",
    "ai",
)
HAS_VALUES = (
    "tags",
    "evidence",
    "cvss",
    "payout",
    "poc",
    "notes",
    "remediation",
    "reference",
    "program",
    "cwe",
    "bonus",
    "reward",
)

COMPARISON = re.compile(r"^(>=|<=|>|<|=)?\s*(-?\d+(?:\.\d+)?)$")
DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

# A token is field:"value", field:value, "phrase" or a word, optionally prefixed with "-".
TOKEN = re.compile(
    r"""(?P<neg>-)?
        (?:
            (?P<field>[A-Za-zÀ-ỹ_]+):(?:"(?P<fvalue_q>[^"]*)"|(?P<fvalue>[^\s"]+))
          | "(?P<phrase>[^"]*)"
          | (?P<word>[^\s"]+)
        )""",
    re.VERBOSE | re.UNICODE,
)


def strip_accents(value: str) -> str:
    """Fold diacritics so 'lo hong' matches 'lỗ hổng', like the FTS ``remove_diacritics 2`` option."""
    decomposed = unicodedata.normalize("NFD", value)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


@dataclass(frozen=True)
class Comparison:
    """A numeric bound such as ``cvss:>=8.1``."""

    op: str
    value: float
    negated: bool = False


@dataclass
class ParsedQuery:
    raw: str = ""
    words: list[str] = field(default_factory=list)
    phrases: list[str] = field(default_factory=list)
    excluded_words: list[str] = field(default_factory=list)
    excluded_phrases: list[str] = field(default_factory=list)
    # canonical field -> list of (value, negated)
    filters: dict[str, list[tuple[str, bool]]] = field(default_factory=dict)
    # canonical field -> every bound given, so `cvss:>=5 cvss:<=8` is a range
    comparisons: dict[str, list[Comparison]] = field(default_factory=dict)
    kinds: tuple[str, ...] = KINDS
    warnings: list[str] = field(default_factory=list)

    @property
    def has_text(self) -> bool:
        return bool(self.words or self.phrases)

    @property
    def is_empty(self) -> bool:
        return not (self.has_text or self.excluded_words or self.excluded_phrases or self.filters or self.comparisons)

    def values(self, name: str, *, negated: bool = False) -> list[str]:
        return [value for value, neg in self.filters.get(name, []) if neg is negated]

    def fts_expression(self) -> str:
        """Render the free text as an FTS5 MATCH expression.

        Words are prefix-matched, phrases are exact, and exclusions use FTS5's binary NOT.
        """

        def quote(value: str) -> str:
            return '"' + value.replace('"', "") + '"'

        positive = [f"{quote(word)}*" for word in self.words] + [quote(p) for p in self.phrases if p.strip()]
        negative = [f"{quote(word)}*" for word in self.excluded_words] + [
            quote(p) for p in self.excluded_phrases if p.strip()
        ]
        # FTS5 cannot express a query made only of exclusions; callers filter those in SQL.
        if not positive:
            return ""
        base = " AND ".join(positive)
        if negative:
            return f"({base}) NOT ({' OR '.join(negative)})"
        return base


def _canonical_field(name: str) -> str | None:
    return FIELD_ALIASES.get(name.casefold())


def parse_query(raw: str) -> ParsedQuery:
    """Parse a query string. Never raises: unknown input becomes text or a warning."""
    parsed = ParsedQuery(raw=raw or "")
    if not raw or not raw.strip():
        return parsed

    kinds: list[str] = []
    excluded_kinds: list[str] = []
    for match in TOKEN.finditer(raw):
        negated = bool(match.group("neg"))
        field_name = match.group("field")

        if field_name:
            value = match.group("fvalue_q")
            if value is None:
                value = match.group("fvalue") or ""
            canonical = _canonical_field(field_name)
            if canonical is None:
                # Unknown field: keep it as text (URLs and host:port contain colons) and warn
                # only when it looks like a filter.
                token_text = match.group(0).lstrip("-")
                if "//" not in token_text and " " not in token_text:
                    parsed.warnings.append(field_name)
                (parsed.excluded_words if negated else parsed.words).append(token_text)
                continue
            _apply_filter(parsed, canonical, value, negated, excluded_kinds if negated else kinds)
            continue

        phrase = match.group("phrase")
        if phrase is not None:
            # Skip terms with nothing to search, such as `""` or `&`.
            if _has_token(phrase):
                (parsed.excluded_phrases if negated else parsed.phrases).append(phrase.strip())
            continue

        word = match.group("word") or ""
        if _has_token(word):
            (parsed.excluded_words if negated else parsed.words).append(word)

    if kinds or excluded_kinds:
        chosen = tuple(dict.fromkeys(kinds)) or KINDS
        parsed.kinds = tuple(kind for kind in chosen if kind not in excluded_kinds)
    return parsed


def _has_token(text: str) -> bool:
    """True when the text contains at least one word character."""
    return bool(re.search(r"\w", text or ""))


def _apply_filter(parsed: ParsedQuery, canonical: str, value: str, negated: bool, kinds: list[str]) -> None:
    value = value.strip()
    if not value:
        return

    if canonical == "kind":
        singular = value.casefold().rstrip("s")
        mapping = {
            "knowledge": "knowledge",
            "research": "knowledge",
            "vuln": "knowledge",
            "finding": "finding",
            "report": "finding",
            "program": "program",
        }
        resolved = mapping.get(singular)
        if resolved:
            kinds.append(resolved)
        else:
            parsed.warnings.append(f"kind:{value}")
        return

    if canonical in ("cvss", "payout"):
        match = COMPARISON.match(value)
        if not match:
            parsed.warnings.append(f"{canonical}:{value}")
            return
        op = match.group(1) or "="
        parsed.comparisons.setdefault(canonical, []).append(
            Comparison(op=op, value=float(match.group(2)), negated=negated)
        )
        return

    if canonical in ("after", "before"):
        if not DATE.match(value):
            parsed.warnings.append(f"{canonical}:{value}")
            return
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            parsed.warnings.append(f"{canonical}:{value}")
            return
        parsed.filters.setdefault(canonical, []).append((value, negated))
        return

    if canonical == "is" and value.casefold() not in IS_VALUES:
        parsed.warnings.append(f"is:{value}")
        return
    if canonical == "has" and value.casefold() not in HAS_VALUES:
        parsed.warnings.append(f"has:{value}")
        return

    if canonical == "cwe":
        # Accept 352, cwe-352 and CWE352 as the same value.
        digits = re.sub(r"\D", "", value)
        parsed.filters.setdefault("cwe", []).append((digits or value, negated))
        return

    parsed.filters.setdefault(canonical, []).append((value, negated))


def compose_query(text: str = "", **fields: str) -> str:
    """Fold dropdown filter values into a query string, quoted so ``OAuth / SSO`` stays one value."""
    parts = [text.strip()] if text and text.strip() else []
    for name, raw in fields.items():
        value = (raw or "").strip()
        if not value:
            continue
        parts.append(f'{name}:"{value}"' if re.search(r"[\s\"]", value) else f"{name}:{value}")
    return " ".join(parts)


def describe(parsed: ParsedQuery) -> list[str]:
    """Human-readable chips describing what the query actually asked for."""
    chips = [f'"{phrase}"' for phrase in parsed.phrases]
    chips.extend(parsed.words)
    chips.extend(f"-{word}" for word in parsed.excluded_words)
    chips.extend(
        f"{'-' if negated else ''}{name}:{value}"
        for name, entries in parsed.filters.items()
        for value, negated in entries
    )
    chips.extend(
        f"{'-' if bound.negated else ''}{name}:{bound.op}{bound.value:g}"
        for name, bounds in parsed.comparisons.items()
        for bound in bounds
    )
    return chips


# Statuses that no longer need attention; `is:open` is the complement.
CLOSED_STATUSES = ("rejected", "duplicate", "out_of_scope", "informative", "archived", "paid", "resolved")


def highlight(raw_snippet: str) -> Markup:
    """Escape an FTS snippet, then turn its highlight markers into <mark>.

    Snippets often hold real payloads, so escaping happens before any markup is added.
    """
    if not raw_snippet:
        return Markup("")
    safe = str(escape(raw_snippet))
    safe = safe.replace(HIGHLIGHT_OPEN, "<mark>").replace(HIGHLIGHT_CLOSE, "</mark>")
    return Markup(safe)


def plain_snippet(value) -> str:
    """A snippet as plain text without highlight markup, for clients that insert it as text."""
    if not value:
        return ""
    text = str(value).replace("<mark>", "").replace("</mark>", "")
    return html.unescape(text)[:160]


def _like(value: str) -> str:
    return f"%{value}%"


def _text_matches(haystack: str, parsed: ParsedQuery) -> bool:
    """Diacritic-folded free-text match used for the non-FTS fallback path."""
    folded = strip_accents(haystack).casefold()
    for term in parsed.words + [p for p in parsed.phrases if p.strip()]:
        if strip_accents(term).casefold() not in folded:
            return False
    for term in parsed.excluded_words + [p for p in parsed.excluded_phrases if p.strip()]:
        if strip_accents(term).casefold() in folded:
            return False
    return True


def _total_reward_sql():
    """SQL expression for payout + bonus, treating a missing part as zero."""
    return func.coalesce(Finding.payout, 0.0) + func.coalesce(Finding.bonus, 0.0)


def _downgraded_clause():
    """SQL for findings the program rated below our severity; empty program_severity means no re-rating."""
    ranking = {name: index for index, name in enumerate(SEVERITIES)}
    theirs = case(ranking, value=Finding.program_severity, else_=-1)
    ours = case(ranking, value=Finding.severity, else_=-1)
    return and_(Finding.program_severity != "", theirs >= 0, ours >= 0, theirs < ours)


def _compare(column, comparison: Comparison):
    if comparison.op == ">":
        return column > comparison.value
    if comparison.op == ">=":
        return column >= comparison.value
    if comparison.op == "<":
        return column < comparison.value
    if comparison.op == "<=":
        return column <= comparison.value
    return column == comparison.value


def _as_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)


def _rewarded():
    return or_(Finding.payout.isnot(None), Finding.bonus.isnot(None))


@dataclass(frozen=True)
class KindFilters:
    """SQL for every filter one record kind understands; a filter missing here cannot be answered."""

    fields: dict[str, Callable[[str], Any]]
    flags: dict[str, dict[str, Callable[[], Any]]]  # "is" and "has" values
    comparisons: dict[str, Callable[[Comparison], Any]]


KNOWLEDGE_FILTERS = KindFilters(
    fields={
        "tag": lambda value: KnowledgeEntry.tags.any(Tag.name == normalize_tag(value)),
        "severity": lambda value: KnowledgeEntry.default_severity == value.casefold(),
        "bug_type": lambda value: KnowledgeEntry.bug_type.ilike(_like(value)),
        "cwe": lambda value: KnowledgeEntry.cwe.ilike(_like(value)),
        "technology": lambda value: KnowledgeEntry.technology.ilike(_like(value)),
        "endpoint": lambda value: KnowledgeEntry.endpoint.ilike(_like(value)),
        # Program, status and target live on findings, so they become existence checks.
        "program": lambda value: KnowledgeEntry.findings.any(Finding.program.has(Program.name.ilike(_like(value)))),
        "status": lambda value: KnowledgeEntry.findings.any(Finding.status == value.casefold()),
        "target": lambda value: KnowledgeEntry.findings.any(Finding.target.ilike(_like(value))),
        "program_id": lambda value: KnowledgeEntry.findings.any(Finding.program_id == value),
        "currency": lambda value: KnowledgeEntry.findings.any(Finding.currency == value.upper()),
        "after": lambda value: KnowledgeEntry.updated_at >= _as_datetime(value),
        "before": lambda value: KnowledgeEntry.updated_at < _as_datetime(value),
    },
    flags={
        "is": {
            "draft": lambda: KnowledgeEntry.is_draft.is_(True),
            "ai": lambda: and_(KnowledgeEntry.use_for_ai.is_(True), KnowledgeEntry.is_draft.is_(False)),
            "linked": lambda: KnowledgeEntry.findings.any(),
            "orphan": lambda: ~KnowledgeEntry.findings.any(),
            "archived": lambda: KnowledgeEntry.findings.any(Finding.program.has(Program.archived.is_(True))),
            "open": lambda: KnowledgeEntry.findings.any(Finding.status.notin_(CLOSED_STATUSES)),
            "submitted": lambda: KnowledgeEntry.findings.any(Finding.status == "submitted"),
            "paid": lambda: KnowledgeEntry.findings.any(Finding.status == "paid"),
            "accepted": lambda: KnowledgeEntry.findings.any(Finding.status == "accepted"),
            "duplicate": lambda: KnowledgeEntry.findings.any(Finding.status == "duplicate"),
            "rewarded": lambda: KnowledgeEntry.findings.any(_rewarded()),
            "downgraded": lambda: KnowledgeEntry.findings.any(_downgraded_clause()),
        },
        "has": {
            "evidence": lambda: KnowledgeEntry.evidence.any(),
            "tags": lambda: KnowledgeEntry.tags.any(),
            "cvss": lambda: KnowledgeEntry.cvss_score.isnot(None),
            "payout": lambda: KnowledgeEntry.findings.any(Finding.payout.isnot(None)),
            "bonus": lambda: KnowledgeEntry.findings.any(Finding.bonus.isnot(None)),
            "reward": lambda: KnowledgeEntry.findings.any(_rewarded()),
            "poc": lambda: KnowledgeEntry.markdown.contains("```"),
            "notes": lambda: KnowledgeEntry.research_notes != "",
            "remediation": lambda: KnowledgeEntry.remediation != "",
            "reference": lambda: KnowledgeEntry.references != "",
            "program": lambda: KnowledgeEntry.findings.any(),
            "cwe": lambda: KnowledgeEntry.cwe != "",
        },
    },
    comparisons={
        "cvss": lambda bound: and_(KnowledgeEntry.cvss_score.isnot(None), _compare(KnowledgeEntry.cvss_score, bound)),
        "payout": lambda bound: KnowledgeEntry.findings.any(and_(_rewarded(), _compare(_total_reward_sql(), bound))),
    },
)

FINDING_FILTERS = KindFilters(
    fields={
        "severity": lambda value: Finding.severity == value.casefold(),
        "status": lambda value: Finding.status == value.casefold(),
        "program": lambda value: Finding.program.has(Program.name.ilike(_like(value))),
        "target": lambda value: Finding.target.ilike(_like(value)),
        "program_id": lambda value: Finding.program_id == value,
        "bug_type": lambda value: Finding.knowledge.has(KnowledgeEntry.bug_type.ilike(_like(value))),
        "cwe": lambda value: Finding.knowledge.has(KnowledgeEntry.cwe.ilike(_like(value))),
        "tag": lambda value: Finding.knowledge.has(KnowledgeEntry.tags.any(Tag.name == normalize_tag(value))),
        "currency": lambda value: Finding.currency == value.upper(),
        "after": lambda value: Finding.updated_at >= _as_datetime(value),
        "before": lambda value: Finding.updated_at < _as_datetime(value),
    },
    flags={
        "is": {
            "open": lambda: Finding.status.notin_(CLOSED_STATUSES),
            "submitted": lambda: Finding.status == "submitted",
            "paid": lambda: Finding.status == "paid",
            "accepted": lambda: Finding.status == "accepted",
            "archived": lambda: Finding.program.has(Program.archived.is_(True)),
            "draft": lambda: Finding.status == "draft",
            "duplicate": lambda: Finding.status == "duplicate",
            "rewarded": _rewarded,
            "downgraded": _downgraded_clause,
        },
        "has": {
            "payout": lambda: Finding.payout.isnot(None),
            "bonus": lambda: Finding.bonus.isnot(None),
            "reward": _rewarded,
            "notes": lambda: Finding.private_notes != "",
            "evidence": lambda: Finding.knowledge.has(KnowledgeEntry.evidence.any()),
        },
    },
    comparisons={
        "payout": lambda bound: and_(_rewarded(), _compare(_total_reward_sql(), bound)),
        "cvss": lambda bound: Finding.knowledge.has(
            and_(KnowledgeEntry.cvss_score.isnot(None), _compare(KnowledgeEntry.cvss_score, bound))
        ),
    },
)

PROGRAM_FILTERS = KindFilters(
    fields={
        "program": lambda value: Program.name.ilike(_like(value)),
        "after": lambda value: Program.updated_at >= _as_datetime(value),
        "before": lambda value: Program.updated_at < _as_datetime(value),
    },
    flags={"is": {"archived": lambda: Program.archived.is_(True)}, "has": {}},
    comparisons={},
)

KIND_FILTERS = {"knowledge": KNOWLEDGE_FILTERS, "finding": FINDING_FILTERS, "program": PROGRAM_FILTERS}


def _filtered(query, parsed: ParsedQuery, filters: KindFilters):
    """Add a WHERE clause for every filter in the query that this kind understands."""
    clauses = []
    for name, entries in parsed.filters.items():
        for value, negated in entries:
            if name in filters.flags:
                build = filters.flags[name].get(value.casefold())
                clause = build() if build else None
            else:
                build = filters.fields.get(name)
                clause = build(value) if build else None
            if clause is not None:
                clauses.append(~clause if negated else clause)
    for name, bounds in parsed.comparisons.items():
        build = filters.comparisons.get(name)
        if build:
            clauses.extend(~build(bound) if bound.negated else build(bound) for bound in bounds)
    return query.filter(*clauses) if clauses else query


def knowledge_rows(
    session: Session, parsed: ParsedQuery, limit: int = 500
) -> tuple[list[KnowledgeEntry], int, dict[str, tuple[float, str]]]:
    """Ranked KnowledgeEntry objects for a parsed query, used by the registry pages."""
    expression = parsed.fts_expression()
    ranked: dict[str, tuple[float, str]] = {}
    if expression:
        matches = fts_knowledge_matches(session, expression, limit=600)
        if not matches:
            return [], 0, {}
        ranked = {entry_id: (rank, snippet) for entry_id, rank, snippet in matches}

    query = session.query(KnowledgeEntry).options(
        selectinload(KnowledgeEntry.findings).selectinload(Finding.program),
        selectinload(KnowledgeEntry.evidence),
        selectinload(KnowledgeEntry.tags),
    )
    if ranked:
        query = query.filter(KnowledgeEntry.id.in_(list(ranked)))
    rows = _filtered(query, parsed, KNOWLEDGE_FILTERS).limit(1200).all()

    if expression:
        # Keep the BM25 order from the index.
        rows.sort(key=lambda entry: ranked.get(entry.id, (0.0, ""))[0])
    else:
        if not _sql_only_ok(parsed):
            rows = [row for row in rows if _text_matches(_knowledge_haystack(row), parsed)]
        rows.sort(key=lambda entry: entry.updated_at, reverse=True)

    return rows[:limit], len(rows), ranked


def _display_snippet(raw_snippet: str, title: str, fallback: str) -> Markup:
    """Use the summary when the best snippet only repeats the title."""
    if not raw_snippet:
        return escape(fallback[:180])
    plain = raw_snippet.replace(HIGHLIGHT_OPEN, "").replace(HIGHLIGHT_CLOSE, "").strip().strip("…").strip()
    if plain and title and plain.casefold() in title.casefold() and fallback.strip():
        return escape(fallback[:180])
    return highlight(raw_snippet)


def _search_knowledge(session: Session, parsed: ParsedQuery, limit: int) -> tuple[list[dict], int]:
    rows, total, ranked = knowledge_rows(session, parsed, limit=limit)
    results = []
    for entry in rows:
        rank, snippet = ranked.get(entry.id, (0.0, ""))
        results.append(
            {
                "kind": "knowledge",
                "id": entry.id,
                "title": entry.title,
                "url": f"/knowledge/{entry.id}",
                "severity": entry.default_severity,
                "bug_type": entry.bug_type,
                "cwe": entry.cwe,
                "cvss": entry.cvss_score,
                "is_draft": entry.is_draft,
                "programs": [finding.program.name for finding in entry.findings if finding.program],
                "evidence_count": len(entry.evidence),
                "tags": entry.tag_names,
                "updated_at": entry.updated_at,
                "snippet": _display_snippet(snippet, entry.title, entry.summary),
                "score": -rank,
            }
        )
    return results, total


def _knowledge_haystack(entry: KnowledgeEntry) -> str:
    return " ".join(
        filter(
            None,
            [
                entry.title,
                entry.summary,
                entry.markdown,
                entry.bug_type,
                entry.endpoint,
                entry.technology,
                entry.cwe,
                " ".join(entry.tag_names),
                entry.research_notes,
            ],
        )
    )


def _sql_only_ok(parsed: ParsedQuery) -> bool:
    """True when the query has no free text, so no Python filtering is needed."""
    return not (parsed.has_text or parsed.excluded_words or parsed.excluded_phrases)


def finding_rows(
    session: Session, parsed: ParsedQuery, limit: int = 500
) -> tuple[list[Finding], int, dict[str, tuple[float, str]]]:
    """Ranked Finding rows for a parsed query."""
    expression = parsed.fts_expression()
    ranked: dict[str, tuple[float, str]] = {}
    allowed_ids: set[str] | None = None

    if expression:
        # A finding matches on its own fields or through the text of its knowledge entry.
        ranked = {
            entity_id: (rank, snippet)
            for entity_id, rank, snippet in fts_entity_matches(session, "finding", expression, limit=600)
        }
        knowledge_ids = [entry_id for entry_id, _rank, _snip in fts_knowledge_matches(session, expression, limit=600)]
        via_knowledge: set[str] = set()
        if knowledge_ids:
            via_knowledge = {
                row[0] for row in session.query(Finding.id).filter(Finding.knowledge_id.in_(knowledge_ids)).all()
            }
        allowed_ids = set(ranked) | via_knowledge
        if not allowed_ids:
            return [], 0, {}

    query = session.query(Finding).options(selectinload(Finding.program), selectinload(Finding.knowledge))
    if allowed_ids is not None:
        query = query.filter(Finding.id.in_(list(allowed_ids)))
    rows = _filtered(query, parsed, FINDING_FILTERS).limit(1200).all()
    if expression:
        rows.sort(key=lambda finding: ranked.get(finding.id, (1000.0, ""))[0])
    else:
        if not _sql_only_ok(parsed):
            rows = [row for row in rows if _text_matches(_finding_haystack(row), parsed)]
        rows.sort(key=lambda finding: finding.updated_at, reverse=True)

    return rows[:limit], len(rows), ranked


def _search_findings(session: Session, parsed: ParsedQuery, limit: int) -> tuple[list[dict], int]:
    rows, total, ranked = finding_rows(session, parsed, limit=limit)
    results = []
    for finding in rows:
        rank, snippet = ranked.get(finding.id, (0.0, ""))
        results.append(
            {
                "kind": "finding",
                "id": finding.id,
                "title": finding.knowledge.title if finding.knowledge else finding.target,
                "url": finding.url,
                "program": finding.program.name if finding.program else "",
                "target": finding.target,
                "severity": finding.severity,
                "status": finding.status,
                "report_id": finding.report_id,
                "payout": finding.payout,
                "updated_at": finding.updated_at,
                "snippet": _display_snippet(
                    snippet, finding.knowledge.title if finding.knowledge else "", finding.target or finding.scope or ""
                ),
                "score": -rank,
            }
        )
    return results, total


def _finding_haystack(finding: Finding) -> str:
    parts = [finding.target, finding.scope, finding.report_id, finding.private_notes, finding.status]
    if finding.knowledge:
        parts += [finding.knowledge.title, finding.knowledge.summary]
    if finding.program:
        parts.append(finding.program.name)
    return " ".join(filter(None, parts))


def _search_programs(session: Session, parsed: ParsedQuery, limit: int) -> tuple[list[dict], int]:
    expression = parsed.fts_expression()
    ranked: dict[str, tuple[float, str]] = {}
    if expression:
        ranked = {
            entity_id: (rank, snippet)
            for entity_id, rank, snippet in fts_entity_matches(session, "program", expression, limit=400)
        }
        if not ranked:
            return [], 0

    query = session.query(Program).options(selectinload(Program.findings))
    if ranked:
        query = query.filter(Program.id.in_(list(ranked)))
    rows = _filtered(query, parsed, PROGRAM_FILTERS).limit(600).all()
    if expression:
        rows.sort(key=lambda program: ranked.get(program.id, (1000.0, ""))[0])
    else:
        if not _sql_only_ok(parsed):
            rows = [
                row
                for row in rows
                if _text_matches(" ".join(filter(None, [row.name, row.platform, row.handle, row.notes])), parsed)
            ]
        rows.sort(key=lambda program: program.updated_at, reverse=True)

    total = len(rows)
    results = []
    for program in rows[:limit]:
        rank, snippet = ranked.get(program.id, (0.0, ""))
        results.append(
            {
                "kind": "program",
                "id": program.id,
                "title": program.name,
                "url": f"/programs/{program.id}",
                "platform": program.platform,
                "handle": program.handle,
                "archived": program.archived,
                "finding_count": len(program.findings),
                "updated_at": program.updated_at,
                "snippet": highlight(snippet) if snippet else escape(program.notes[:180]),
                "score": -rank,
            }
        )
    return results, total


def kind_can_answer(parsed: ParsedQuery, kind: str) -> bool:
    """True when every filter in the query means something for this record kind.

    A kind that cannot evaluate a filter is left out of the results instead of being returned unfiltered.
    """
    filters = KIND_FILTERS[kind]
    for name, entries in parsed.filters.items():
        if name in filters.flags:
            if any(value.casefold() not in filters.flags[name] for value, _negated in entries):
                return False
        elif name not in filters.fields:
            return False
    return all(name in filters.comparisons for name in parsed.comparisons)


def run_search(session: Session, parsed: ParsedQuery, *, limit: int = 40) -> dict:
    """Run a parsed query for every requested kind. Totals are counted before the display limit."""
    empty: tuple[list[dict], int] = ([], 0)

    def wanted(kind: str) -> bool:
        return kind in parsed.kinds and kind_can_answer(parsed, kind)

    knowledge = _search_knowledge(session, parsed, limit) if wanted("knowledge") else empty
    findings = _search_findings(session, parsed, limit) if wanted("finding") else empty
    programs = _search_programs(session, parsed, limit) if wanted("program") else empty
    return {
        "knowledge": knowledge[0],
        "knowledge_total": knowledge[1],
        "findings": findings[0],
        "findings_total": findings[1],
        "programs": programs[0],
        "programs_total": programs[1],
        "total": knowledge[1] + findings[1] + programs[1],
    }
