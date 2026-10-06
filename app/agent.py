"""Agent API: one tool catalogue served over WebMCP and MCP.

- WebMCP: app.js registers the tools with ``document.modelContext`` so an in-browser
  agent acts as the signed-in user (``POST /api/agent/call`` with the CSRF token).
- MCP: ``POST /mcp`` (JSON-RPC) for external clients, authenticated with
  ``VULNS_AGENT_TOKEN``.

Write tools call the same route handlers as the web forms, so validation, Markdown
files and search indexing behave exactly as they do for a manual edit.
"""

from __future__ import annotations

import hmac
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from .database import backlink_entries
from .forms import build_bounty
from .markdown_import import MarkdownImportError, parse_markdown_upload
from .models import Evidence, Finding, KnowledgeEntry, Program
from .routes.evidence import evidence_delete
from .routes.findings import finding_create, finding_delete, finding_edit
from .routes.knowledge import knowledge_create, knowledge_delete, knowledge_edit
from .routes.programs import program_create, program_delete, program_edit
from .search import parse_query, plain_snippet, run_search
from .security import authenticated, csrf_token
from .stats import response_metrics, rewards_by_currency, workspace_snapshot
from .taxonomy import BUG_TYPES, CURRENCIES, SEVERITIES, STATUSES
from .web import refresh_markdown

PROTOCOL_VERSION = "2025-06-18"
SERVER_VERSION = "1.0.0"
MARKDOWN_LIMIT = 60_000
MAX_PAGE = 50
MAX_WINDOW = 500

# Text shown to agents: server instructions and tool descriptions.

INSTRUCTIONS = """VulnS is a single-user bug-bounty workspace. Three record kinds:
- program: a bounty program (HackerOne, Bugcrowd...). Container only.
- knowledge: reusable vulnerability research (title, taxonomy, Markdown report). Written once.
- finding: one knowledge entry submitted to one program: target, lifecycle status, dates, bounty.
A knowledge entry can be linked to many programs; each link is a separate finding.
Knowledge entries carry tags (lowercase-hyphen labels such as jwt or account-takeover) and a
use_for_ai flag; drafts and entries with use_for_ai off stay out of the AI export.

Workflow:
1. Orient with get_overview, then locate records with search. Never guess ids.
2. Read a record fully with get_record before changing it.
3. Write with save_program / save_knowledge / save_finding. On update send only the fields to change.
4. delete_record is permanent; use it only when the user asked for a deletion.

Lifecycle: not_submitted > draft > ready_to_submit > submitted > triaged > accepted > resolved > paid,
or a terminal rejected / duplicate / informative / out_of_scope. Dates are YYYY-MM-DD.
Money is never added across currencies."""

QUERY_HELP = (
    "Query language (same as the app's search box). Words are ANDed and prefix-matched; "
    '"exact phrase"; -word excludes. Fields: sev:critical status:submitted type:xss cwe:79 '
    "tag:jwt tech:graphql program:acme endpoint:/oauth target:api. currency:USD cvss:>=8 payout:>500 "
    "after:2026-01-01 before:2026-07-01. Flags: is:open|draft|ai|submitted|accepted|paid|rewarded|"
    "downgraded|duplicate|orphan|linked|archived, has:tags|poc|evidence|cvss|payout|notes|remediation|"
    "reference|program|cwe|bonus|reward. Prefix any filter with - to negate it."
)

_ID = {"type": "string", "description": "Record id (UUID) from search or get_record."}
_DATE = {"type": "string", "description": "YYYY-MM-DD, or empty string to clear."}
_KIND = {"type": "string", "enum": ["program", "knowledge", "finding"]}

TOOLS: list[dict] = [
    {
        "name": "get_overview",
        "title": "Workspace overview",
        "description": (
            "Start here. Returns the dashboard numbers: record counts, the needs-attention queue "
            "(reports waiting on a program, accepted but unpaid, drafts to finish), earnings per "
            "currency, median days to triage and to bounty, status and severity breakdowns, and "
            "how many entries the AI export includes. No input."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "search",
        "title": "Search records",
        "description": (
            "Find programs, knowledge entries and findings. Returns compact rows with ids, ranked "
            "by relevance (or newest first when query is empty). Use kind to restrict to one "
            "record type; an empty query with a kind lists that kind. Page with offset. " + QUERY_HELP
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search text and filters. May be empty when kind is set."},
                "kind": {**_KIND, "description": "Only return this record kind."},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": 10},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_record",
        "title": "Read one record",
        "description": (
            "Read every field of one record. knowledge: full Markdown report, taxonomy, tags, related "
            "and referencing entries, evidence files, AI export status, and every finding that uses it. "
            "finding: target, lifecycle dates, bounty, derived timings, private notes. program: "
            "details, all findings, earnings and response medians."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"kind": _KIND, "id": _ID},
            "required": ["kind", "id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "save_program",
        "title": "Create or update a program",
        "description": (
            "Without id: create a program (name required, unique, case-insensitive). With id: "
            "update only the fields you send. archived=true hides it from new links but keeps its "
            "findings. Returns the saved program."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": _ID,
                "name": {"type": "string", "maxLength": 180},
                "platform": {"type": "string", "description": "e.g. HackerOne, Bugcrowd, Intigriti."},
                "url": {"type": "string", "description": "Program page, absolute http(s) URL or empty."},
                "handle": {"type": "string"},
                "notes": {"type": "string", "description": "Scope and operational notes (Markdown)."},
                "archived": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "save_knowledge",
        "title": "Create or update research",
        "description": (
            "Reusable vulnerability research, independent of any program. Without id: create "
            "(title, bug_type, severity required unless source_markdown supplies them). With id: "
            "update only the fields you send. To submit it to a program, call save_finding next. "
            "markdown is the full report; use headings Summary, Steps to reproduce, Proof of "
            "concept, Impact, Remediation. tags and related_ids replace their lists. use_for_ai=false "
            "keeps a confidential report out of the AI export. source_markdown imports a whole "
            "portable .md document (YAML frontmatter allowed) and lands it as a draft. "
            "draft=false promotes a quick-capture draft."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": _ID,
                "title": {"type": "string", "maxLength": 240},
                "bug_type": {"type": "string", "enum": list(BUG_TYPES)},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "summary": {"type": "string", "description": "One or two sentences: the flaw and its impact."},
                "markdown": {"type": "string", "description": "Full Markdown report body."},
                "endpoint": {"type": "string"},
                "technology": {"type": "string", "description": "Comma separated, e.g. OAuth 2.0, FastAPI."},
                "cwe": {"type": "string", "description": "e.g. CWE-79."},
                "cvss_score": {"type": ["number", "null"], "minimum": 0, "maximum": 10},
                "remediation": {"type": "string"},
                "references": {"type": "string", "description": "One URL or citation per line."},
                "research_notes": {"type": "string", "description": "Private notes, never in the AI export."},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels such as jwt or account-takeover; normalised to lowercase-hyphen form.",
                },
                "use_for_ai": {"type": "boolean", "description": "Include in the AI export (default true)."},
                "related_ids": {"type": "array", "items": {"type": "string"}, "description": "Knowledge ids."},
                "draft": {"type": "boolean"},
                "source_markdown": {"type": "string", "description": "Create only: a complete .md document to import."},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "save_finding",
        "title": "Create or update a submission",
        "description": (
            "A finding links one knowledge entry to one program and tracks that submission. "
            "Without id: create (program_id, knowledge_id required; each pair at most once). With "
            "id: update only the fields you send; changing program_id moves it. Record the bounty "
            "with payout, bonus and currency; send null to clear an amount. program_severity is "
            "the rating the program assigned when it differs from yours."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": _ID,
                "program_id": _ID,
                "knowledge_id": _ID,
                "status": {"type": "string", "enum": list(STATUSES)},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "target": {"type": "string", "description": "Affected host or URL."},
                "scope": {"type": "string"},
                "report_id": {"type": "string", "description": "The platform's report reference."},
                "report_url": {"type": "string", "description": "Absolute http(s) URL or empty."},
                "discovered_at": _DATE,
                "submitted_at": _DATE,
                "triaged_at": _DATE,
                "resolved_at": _DATE,
                "rewarded_at": _DATE,
                "payout": {"type": ["number", "null"], "minimum": 0},
                "bonus": {"type": ["number", "null"], "minimum": 0},
                "currency": {"type": "string", "enum": list(CURRENCIES)},
                "program_severity": {"type": "string", "enum": ["", *SEVERITIES]},
                "duplicate_of": {"type": "string", "description": "Their reference for the original report."},
                "private_notes": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "delete_record",
        "title": "Delete permanently",
        "description": (
            "Permanent; only when the user asked for it. program: removes the program and its "
            "findings, keeps all knowledge. knowledge: removes the research, its evidence files "
            "and every finding using it. finding: unlinks it from the program, keeps the knowledge. "
            "evidence: removes one evidence file. confirm must be true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["program", "knowledge", "finding", "evidence"]},
                "id": _ID,
                "confirm": {"type": "boolean", "const": True},
            },
            "required": ["kind", "id", "confirm"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "consequentialHint": True},
    },
]
TOOL_INDEX = {tool["name"]: tool for tool in TOOLS}


class ToolError(Exception):
    """A failure the agent can act on: the message says what to change."""


# Argument checking: unknown fields and wrong types fail with an actionable message.

_JSON_TYPES = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
    "null": (type(None),),
}


def check_arguments(tool: dict, arguments: Any) -> dict:
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ToolError("arguments must be a JSON object")
    schema = tool["inputSchema"]
    properties = schema.get("properties", {})
    unknown = sorted(set(arguments) - set(properties))
    if unknown:
        raise ToolError(f"Unknown field(s) {unknown}. Allowed: {sorted(properties)}")
    missing = [name for name in schema.get("required", []) if name not in arguments]
    if missing:
        raise ToolError(f"Missing required field(s) {missing}")
    for name, value in arguments.items():
        spec = properties[name]
        types = spec.get("type", [])
        types = [types] if isinstance(types, str) else types
        if types:
            accepted = tuple(python_type for json_type in types for python_type in _JSON_TYPES[json_type])
            # bool is an int in Python; a JSON true must not pass as a number.
            is_bool_mismatch = isinstance(value, bool) and "boolean" not in types
            if is_bool_mismatch or not isinstance(value, accepted):
                raise ToolError(f"{name} must be {' or '.join(types)}")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"{name} must be one of {spec['enum']}")
        if "const" in spec and value != spec["const"]:
            raise ToolError(f"{name} must be {json.dumps(spec['const'])}")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in spec and value < spec["minimum"]:
                raise ToolError(f"{name} must be >= {spec['minimum']}")
            if "maximum" in spec and value > spec["maximum"]:
                raise ToolError(f"{name} must be <= {spec['maximum']}")
    return arguments


# Serialisation. Every record carries its id and a link.


def _when(value) -> str | None:
    return value.isoformat() if value else None


def finding_row(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "title": finding.knowledge.title if finding.knowledge else "",
        "program": finding.program.name if finding.program else "",
        "status": finding.status,
        "severity": finding.severity,
        "target": finding.target,
        "report_id": finding.report_id,
        "total_reward": finding.total_reward,
        "currency": finding.currency,
        "link": finding.url,
    }


def finding_detail(finding: Finding) -> dict:
    return {
        "kind": "finding",
        "id": finding.id,
        "program": {"id": finding.program_id, "name": finding.program.name if finding.program else ""},
        "knowledge": {"id": finding.knowledge_id, "title": finding.knowledge.title if finding.knowledge else ""},
        "status": finding.status,
        "severity": finding.severity,
        "program_severity": finding.program_severity,
        "effective_severity": finding.effective_severity,
        "target": finding.target,
        "scope": finding.scope,
        "report_id": finding.report_id,
        "report_url": finding.report_url,
        "discovered_at": finding.discovered_at,
        "submitted_at": finding.submitted_at,
        "triaged_at": finding.triaged_at,
        "resolved_at": finding.resolved_at,
        "rewarded_at": finding.rewarded_at,
        "payout": finding.payout,
        "bonus": finding.bonus,
        "currency": finding.currency,
        "total_reward": finding.total_reward,
        "duplicate_of": finding.duplicate_of,
        "days_waiting": finding.days_waiting,
        "days_to_triage": finding.days_to_triage,
        "days_to_reward": finding.days_to_reward,
        "days_awaiting_reward": finding.days_awaiting_reward,
        "private_notes": finding.private_notes,
        "updated_at": _when(finding.updated_at),
        "link": finding.url,
    }


def _entry_ref(entry: KnowledgeEntry) -> dict:
    return {"id": entry.id, "title": entry.title}


def knowledge_detail(db: Session, entry: KnowledgeEntry) -> dict:
    related = sorted(entry.related, key=lambda item: (item.title, item.id))
    markdown = entry.markdown or ""
    return {
        "kind": "knowledge",
        "id": entry.id,
        "title": entry.title,
        "bug_type": entry.bug_type,
        "severity": entry.default_severity,
        "draft": entry.is_draft,
        "tags": entry.tag_names,
        "use_for_ai": entry.use_for_ai,
        "in_ai_export": entry.in_ai_export,
        "summary": entry.summary,
        "endpoint": entry.endpoint,
        "technology": entry.technology,
        "cwe": entry.cwe,
        "cvss_score": entry.cvss_score,
        "markdown": markdown[:MARKDOWN_LIMIT],
        "markdown_truncated": len(markdown) > MARKDOWN_LIMIT,
        "remediation": entry.remediation,
        "references": entry.references,
        "research_notes": entry.research_notes,
        "related": [_entry_ref(item) for item in related],
        "referenced_by": [_entry_ref(item) for item in backlink_entries(db, entry.id)],
        "findings": [finding_row(f) for f in sorted(entry.findings, key=lambda f: f.updated_at, reverse=True)],
        "evidence": [
            {
                "id": item.id,
                "filename": item.filename,
                "mime_type": item.mime_type,
                "size_bytes": item.size_bytes,
                "link": f"/evidence/{item.id}",
            }
            for item in entry.evidence
        ],
        "updated_at": _when(entry.updated_at),
        "link": f"/knowledge/{entry.id}",
    }


def program_detail(program: Program) -> dict:
    findings = sorted(program.findings, key=lambda f: f.updated_at, reverse=True)
    metrics = response_metrics(findings)
    return {
        "kind": "program",
        "id": program.id,
        "name": program.name,
        "platform": program.platform,
        "url": program.url,
        "handle": program.handle,
        "notes": program.notes,
        "archived": program.archived,
        "earnings": [{"currency": code, "amount": amount} for code, amount in rewards_by_currency(findings)],
        "median_days_to_triage": metrics["median_triage_days"],
        "median_days_to_bounty": metrics["median_reward_days"],
        "findings": [finding_row(f) for f in findings],
        "updated_at": _when(program.updated_at),
        "link": f"/programs/{program.id}",
    }


def _load(db: Session, kind: str, record_id: str):
    if kind == "program":
        item = (
            db.query(Program)
            .options(selectinload(Program.findings).selectinload(Finding.knowledge))
            .filter(Program.id == record_id)
            .first()
        )
    elif kind == "knowledge":
        item = (
            db.query(KnowledgeEntry)
            .options(
                selectinload(KnowledgeEntry.findings).selectinload(Finding.program),
                selectinload(KnowledgeEntry.evidence),
            )
            .filter(KnowledgeEntry.id == record_id)
            .first()
        )
    elif kind == "finding":
        item = (
            db.query(Finding)
            .options(selectinload(Finding.program), selectinload(Finding.knowledge))
            .filter(Finding.id == record_id)
            .first()
        )
    else:
        item = db.get(Evidence, record_id)
    if not item:
        raise ToolError(f"No {kind} with id {record_id}. Use search to find the right id.")
    return item


def _detail(db: Session, kind: str, record_id: str) -> dict:
    item = _load(db, kind, record_id)
    if kind == "program":
        return program_detail(item)
    if kind == "knowledge":
        return knowledge_detail(db, item)
    return finding_detail(item)


# Tool handlers


def tool_get_overview(db: Session, _request: Request, _args: dict) -> dict:
    snap = workspace_snapshot(db)
    ai_counts = dict(
        db.query(KnowledgeEntry.use_for_ai, func.count(KnowledgeEntry.id))
        .filter(KnowledgeEntry.is_draft.is_(False))
        .group_by(KnowledgeEntry.use_for_ai)
        .all()
    )
    metrics = snap["metrics"]
    return {
        "counts": {
            "open_findings": snap["open_count"],
            "accepted_or_later": snap["accepted_count"],
            "findings": snap["finding_total"],
            "rewarded": metrics["rewarded_count"],
            "knowledge_entries": snap["knowledge_count"],
            "drafts": snap["draft_count"],
            "active_programs": snap["program_count"],
        },
        "needs_attention": {
            "total": snap["attention_total"],
            "awaiting_reply": {
                "count": snap["attention_groups"]["awaiting"],
                "oldest_first": [{**finding_row(f), "days_waiting": f.days_waiting} for f in snap["awaiting"]],
            },
            "accepted_unpaid": {
                "count": snap["attention_groups"]["unpaid"],
                "oldest_first": [
                    {**finding_row(f), "days_since_triage": f.days_awaiting_reward} for f in snap["unpaid"]
                ],
            },
            "drafts_to_finish": {
                "count": snap["attention_groups"]["drafts"],
                "newest_first": [{**_entry_ref(e), "link": f"/knowledge/{e.id}"} for e in snap["drafts"]],
            },
        },
        "earnings": [{"currency": code, "amount": amount} for code, amount in snap["earnings"]],
        "median_days_to_triage": metrics["median_triage_days"],
        "median_days_to_bounty": metrics["median_reward_days"],
        "downgraded_by_program": metrics["downgraded_count"],
        "status_counts": dict(snap["status_counts"]),
        "severity_counts": dict(snap["severity_counts"]),
        "ai_export": {
            "included": ai_counts.get(True, 0),
            "excluded_by_owner": ai_counts.get(False, 0),
            "drafts_waiting": snap["draft_count"],
        },
    }


_SEARCH_KEYS = {
    "knowledge": ("severity", "bug_type", "cwe", "cvss", "tags", "is_draft", "programs", "evidence_count"),
    "finding": ("program", "target", "severity", "status", "report_id", "payout"),
    "program": ("platform", "handle", "archived", "finding_count"),
}


def _search_row(item: dict) -> dict:
    row = {"kind": item["kind"], "id": item["id"], "title": item["title"]}
    row.update({key: item.get(key) for key in _SEARCH_KEYS[item["kind"]]})
    snippet = plain_snippet(item.get("snippet"))
    if snippet:
        row["snippet"] = snippet
    row["updated_at"] = _when(item.get("updated_at"))
    row["link"] = item["url"]
    return row


def _recent_rows(db: Session, kind: str, window: int) -> tuple[list[dict], int]:
    if kind == "program":
        query = db.query(Program).options(selectinload(Program.findings)).order_by(Program.updated_at.desc())
        rows = [
            {
                "kind": "program",
                "id": p.id,
                "title": p.name,
                "platform": p.platform,
                "handle": p.handle,
                "archived": p.archived,
                "finding_count": len(p.findings),
                "updated_at": _when(p.updated_at),
                "link": f"/programs/{p.id}",
            }
            for p in query.limit(window)
        ]
        return rows, query.count()
    if kind == "knowledge":
        query = (
            db.query(KnowledgeEntry)
            .options(
                selectinload(KnowledgeEntry.findings).selectinload(Finding.program),
                selectinload(KnowledgeEntry.evidence),
            )
            .order_by(KnowledgeEntry.updated_at.desc())
        )
        rows = [
            {
                "kind": "knowledge",
                "id": e.id,
                "title": e.title,
                "severity": e.default_severity,
                "bug_type": e.bug_type,
                "cwe": e.cwe,
                "cvss": e.cvss_score,
                "tags": e.tag_names,
                "is_draft": e.is_draft,
                "programs": [f.program.name for f in e.findings if f.program],
                "evidence_count": len(e.evidence),
                "updated_at": _when(e.updated_at),
                "link": f"/knowledge/{e.id}",
            }
            for e in query.limit(window)
        ]
        return rows, query.count()
    query = (
        db.query(Finding)
        .options(selectinload(Finding.program), selectinload(Finding.knowledge))
        .order_by(Finding.updated_at.desc())
    )
    rows = [{"kind": "finding", **finding_row(f), "updated_at": _when(f.updated_at)} for f in query.limit(window)]
    return rows, query.count()


def tool_search(db: Session, _request: Request, args: dict) -> dict:
    query = (args.get("query") or "").strip()
    kind = args.get("kind")
    limit = args.get("limit", 10)
    offset = args.get("offset", 0)
    window = min(offset + limit, MAX_WINDOW)
    if offset >= MAX_WINDOW:
        raise ToolError(f"offset must be below {MAX_WINDOW}; narrow the query instead of paging further")
    warnings: list[str] = []
    if not query:
        if not kind:
            raise ToolError("Give a query, or a kind to list the newest records of that kind")
        rows, total = _recent_rows(db, kind, window)
    else:
        parsed = parse_query(f"{query} kind:{kind}" if kind else query)
        warnings = list(parsed.warnings)
        if parsed.is_empty:
            raise ToolError("The query has no searchable words or filters")
        results = run_search(db, parsed, limit=window)
        rows = [_search_row(item) for item in [*results["knowledge"], *results["findings"], *results["programs"]]]
        total = results["total"]
    page = rows[offset : offset + limit]
    out: dict = {"total": total, "returned": len(page), "results": page}
    if offset + len(page) < min(total, MAX_WINDOW):
        out["next_offset"] = offset + len(page)
    if warnings:
        out["unrecognised_filters"] = warnings
    return out


def tool_get_record(db: Session, _request: Request, args: dict) -> dict:
    return _detail(db, args["kind"], args["id"])


def _id_from_location(response: Response, pattern: str) -> str:
    location = response.headers.get("location", "")
    parts = urlsplit(location)
    if pattern == "finding_id":
        return parse_qs(parts.query).get("finding_id", [""])[0]
    segments = parts.path.strip("/").split("/")
    return segments[1] if len(segments) > 1 else ""


def _form_token(request: Request) -> str:
    """CSRF value for the reused form handlers; bearer calls have no session, so pass a placeholder."""
    return "bearer" if getattr(request.state, "csrf_exempt", False) else csrf_token(request)


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def tool_save_program(db: Session, request: Request, args: dict) -> dict:
    token = _form_token(request)
    record_id = args.get("id")
    if record_id:
        current = _load(db, "program", record_id)
        merged = {
            field: args.get(field, getattr(current, field))
            for field in ("name", "platform", "url", "handle", "notes", "archived")
        }
        program_edit(request, record_id, csrf=token, db=db, **merged)
        return {"created": False, "program": _detail(db, "program", record_id)}
    if not args.get("name"):
        raise ToolError("name is required to create a program")
    response = program_create(
        request,
        name=args["name"],
        platform=args.get("platform", ""),
        url=args.get("url", ""),
        handle=args.get("handle", ""),
        notes=args.get("notes", ""),
        archived=args.get("archived", False),
        csrf=token,
        db=db,
    )
    return {"created": True, "program": _detail(db, "program", _id_from_location(response, "path"))}


_KNOWLEDGE_TEXT = (
    "summary",
    "markdown",
    "endpoint",
    "technology",
    "cwe",
    "remediation",
    "references",
    "research_notes",
)


async def tool_save_knowledge(db: Session, request: Request, args: dict) -> dict:
    token = _form_token(request)
    record_id = args.get("id")
    if record_id and "source_markdown" in args:
        raise ToolError("source_markdown is only for creating; send markdown to change an existing report")
    common = {"uploads": None, "csrf": token, "db": db}
    if record_id:
        current = _load(db, "knowledge", record_id)
        was_draft = current.is_draft
        fields = {name: args.get(name, getattr(current, name)) for name in _KNOWLEDGE_TEXT}
        fields["title"] = args.get("title", current.title)
        fields["bug_type"] = args.get("bug_type", current.bug_type)
        fields["default_severity"] = args.get("severity", current.default_severity)
        fields["cvss_score"] = _text(args.get("cvss_score", current.cvss_score))
        fields["related_ids"] = list(args.get("related_ids", current.related_ids))
        fields["tags"] = ", ".join(args["tags"]) if "tags" in args else None
        fields["use_for_ai"] = _flag_values(args.get("use_for_ai"))
        await knowledge_edit(request, record_id, **fields, **common)
        # Unlike the web form, an agent edit keeps the draft flag unless `draft` is given.
        _set_draft(db, request, record_id, args.get("draft", was_draft))
        return {"created": False, "knowledge": _detail(db, "knowledge", record_id)}

    imported: dict = {}
    draft_default = False
    if "source_markdown" in args:
        try:
            parsed = parse_markdown_upload(
                "import.md",
                args["source_markdown"].encode("utf-8"),
                bug_types=BUG_TYPES,
                severities=SEVERITIES,
            )
        except MarkdownImportError as exc:
            raise ToolError(f"source_markdown rejected: {exc}") from exc
        imported = {
            "title": parsed.title,
            "bug_type": parsed.bug_type,
            "severity": parsed.default_severity,
            "summary": parsed.summary,
            "markdown": parsed.markdown,
            "endpoint": parsed.endpoint,
            "technology": parsed.technology,
            "cwe": parsed.cwe,
            "cvss_score": parsed.cvss_score,
            "remediation": parsed.remediation,
            "references": parsed.references,
            "research_notes": parsed.research_notes,
            "tags": parsed.tags,
            "use_for_ai": parsed.use_for_ai,
        }
        draft_default = True
    values = {**imported, **{key: value for key, value in args.items() if key != "source_markdown"}}
    missing = [name for name in ("title", "bug_type", "severity") if not values.get(name)]
    if missing:
        raise ToolError(f"Missing {missing} to create a knowledge entry")
    response = await knowledge_create(
        request,
        title=values["title"],
        bug_type=values["bug_type"],
        default_severity=values["severity"],
        cvss_score=_text(values.get("cvss_score")),
        related_ids=list(values.get("related_ids", [])),
        tags=", ".join(values.get("tags", [])),
        use_for_ai=_flag_values(values.get("use_for_ai")),
        **{name: values.get(name, "") for name in _KNOWLEDGE_TEXT},
        **common,
    )
    new_id = _id_from_location(response, "path")
    _set_draft(db, request, new_id, values.get("draft", draft_default))
    return {"created": True, "knowledge": _detail(db, "knowledge", new_id)}


def _flag_values(value: bool | None) -> list[str] | None:
    """A boolean in the shape the form handlers receive from a checkbox."""
    return None if value is None else (["1"] if value else ["0"])


def _set_draft(db: Session, request: Request, record_id: str, draft: bool) -> None:
    db.expire_all()
    entry = _load(db, "knowledge", record_id)
    if entry.is_draft != bool(draft):
        entry.is_draft = bool(draft)
        db.commit()
        refresh_markdown(request, db, entry)


_FINDING_TEXT = ("target", "scope", "report_id", "report_url", "discovered_at", "submitted_at", "private_notes")
_BOUNTY = (
    "triaged_at",
    "resolved_at",
    "rewarded_at",
    "payout",
    "bonus",
    "currency",
    "program_severity",
    "duplicate_of",
)


def tool_save_finding(db: Session, request: Request, args: dict) -> dict:
    token = _form_token(request)
    record_id = args.get("id")
    current = _load(db, "finding", record_id) if record_id else None

    def pick(name: str, fallback: Any = "") -> Any:
        if name in args:
            return args[name]
        return getattr(current, name) if current is not None else fallback

    if current is None:
        missing = [name for name in ("program_id", "knowledge_id") if not args.get(name)]
        if missing:
            raise ToolError(f"Missing {missing} to create a finding")
    knowledge_severity = None
    if current is None and "severity" not in args:
        knowledge_severity = _load(db, "knowledge", args["knowledge_id"]).default_severity
    bounty = build_bounty(**{name: _text(pick(name, "USD" if name == "currency" else "")) for name in _BOUNTY})
    fields = {
        "program_id": pick("program_id"),
        "knowledge_id": pick("knowledge_id"),
        "status": pick("status", "not_submitted"),
        "severity": pick("severity", knowledge_severity or "medium"),
        **{name: _text(pick(name)) for name in _FINDING_TEXT},
        "bounty": bounty,
        "csrf": token,
        "db": db,
    }
    if current is not None:
        finding_edit(request, record_id, **fields)
        db.expire_all()
        return {"created": False, "finding": _detail(db, "finding", record_id)}
    response = finding_create(request, **fields)
    return {"created": True, "finding": _detail(db, "finding", _id_from_location(response, "finding_id"))}


def tool_delete_record(db: Session, request: Request, args: dict) -> dict:
    kind, record_id = args["kind"], args["id"]
    item = _load(db, kind, record_id)
    label = (
        getattr(item, "name", None)
        or getattr(item, "title", None)
        or getattr(item, "filename", None)
        or (item.knowledge.title if isinstance(item, Finding) and item.knowledge else record_id)
    )
    handler = {
        "program": program_delete,
        "knowledge": knowledge_delete,
        "finding": finding_delete,
        "evidence": evidence_delete,
    }[kind]
    handler(request, record_id, csrf=_form_token(request), db=db)
    return {"deleted": {"kind": kind, "id": record_id, "label": label}}


HANDLERS = {
    "get_overview": tool_get_overview,
    "search": tool_search,
    "get_record": tool_get_record,
    "save_program": tool_save_program,
    "save_knowledge": tool_save_knowledge,
    "save_finding": tool_save_finding,
    "delete_record": tool_delete_record,
}
assert set(HANDLERS) == set(TOOL_INDEX), "every tool needs exactly one handler"


async def call_tool(request: Request, name: str, arguments: Any) -> tuple[dict, bool]:
    """Run one tool. Returns (payload, is_error); never raises for agent mistakes."""
    tool = TOOL_INDEX.get(name)
    if tool is None:
        return {"error": f"Unknown tool {name!r}. Tools: {sorted(TOOL_INDEX)}"}, True
    db = request.app.state.session_factory()
    try:
        args = check_arguments(tool, arguments)
        result = HANDLERS[name](db, request, args)
        if hasattr(result, "__await__"):
            result = await result
        return result, False
    except ToolError as exc:
        db.rollback()
        return {"error": str(exc)}, True
    except HTTPException as exc:
        db.rollback()
        detail = exc.detail if isinstance(exc.detail, str) else "Request rejected"
        if exc.status_code == 404:
            detail = "A referenced id does not exist. Use search to find the right id."
        elif exc.status_code == 422 and detail in ("Unprocessable Entity", "Request rejected"):
            detail = "A field has an invalid value; check enums and date formats in the tool schema."
        return {"error": detail, "status": exc.status_code}, True
    finally:
        db.close()


# Transports


def _bearer_ok(request: Request) -> bool:
    token = request.app.state.settings.agent_token
    header = request.headers.get("authorization", "")
    if not token or not header.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(header[7:].strip().encode(), token.encode())


def _same_origin(request: Request) -> bool:
    """Reject cross-site browser calls (DNS rebinding, drive-by pages)."""
    origin = request.headers.get("origin")
    if not origin:
        return True
    return urlsplit(origin).netloc == request.headers.get("host", "")


def _authorize(request: Request, *, write: bool) -> None:
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-origin agent calls are not allowed")
    if _bearer_ok(request):
        # A cross-site page cannot send a bearer token, so the form CSRF check is skipped.
        request.state.csrf_exempt = True
        return
    if not authenticated(request):
        raise HTTPException(status_code=401, detail="Sign in, or send Authorization: Bearer <VULNS_AGENT_TOKEN>")
    if write and not hmac.compare_digest(
        request.headers.get("x-csrf-token", ""), request.session.get("csrf_token", "") or "\0"
    ):
        raise HTTPException(status_code=403, detail="Missing or invalid X-CSRF-Token header")


def tool_manifest() -> list[dict]:
    return [
        {key: tool[key] for key in ("name", "title", "description", "inputSchema", "annotations")} for tool in TOOLS
    ]


router = APIRouter()


@router.get("/api/agent/tools")
def agent_tools(request: Request):
    _authorize(request, write=False)
    return {"instructions": INSTRUCTIONS, "tools": tool_manifest()}


@router.post("/api/agent/call")
async def agent_call(request: Request):
    _authorize(request, write=True)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": 'Body must be JSON: {"tool": ..., "arguments": {...}}'}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Body must be a JSON object"}, status_code=400)
    payload, is_error = await call_tool(request, str(body.get("tool", "")), body.get("arguments"))
    return JSONResponse(payload, status_code=400 if is_error else 200)


@router.get("/mcp")
def mcp_get():
    # No server-initiated stream: every response arrives on its POST.
    return Response(status_code=405, headers={"Allow": "POST"})


@router.post("/mcp")
async def mcp(request: Request):
    _authorize(request, write=True)
    try:
        message = await request.json()
    except ValueError:
        return _rpc_error(None, -32700, "Parse error")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
        return _rpc_error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
    method, rpc_id, params = message["method"], message.get("id"), message.get("params") or {}
    if rpc_id is None:  # notification, e.g. notifications/initialized
        return Response(status_code=202)
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        return _rpc_result(
            rpc_id,
            {
                "protocolVersion": requested or PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "vulns", "title": "VulnS", "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS,
            },
        )
    if method == "ping":
        return _rpc_result(rpc_id, {})
    if method == "tools/list":
        return _rpc_result(rpc_id, {"tools": tool_manifest()})
    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _rpc_error(rpc_id, -32602, "params.name is required")
        payload, is_error = await call_tool(request, params["name"], params.get("arguments"))
        return _rpc_result(
            rpc_id,
            {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                "structuredContent": payload,
                "isError": is_error,
            },
        )
    return _rpc_error(rpc_id, -32601, f"Method not found: {method}")


def _rpc_result(rpc_id: Any, result: dict) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _rpc_error(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})
