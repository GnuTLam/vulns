"""AI export: every vulnerability marked for AI use, as one JSON file or as Markdown files.

Drafts and entries with ``use_for_ai`` off are left out. Text is passed through
``Redactor`` so secrets, real hosts and program names never leave VulnS. Research
notes, program links, bounty data and evidence files are never exported.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime

import yaml
from sqlalchemy.orm import Session, selectinload

from .markdown_store import report_roles, slugify
from .models import Finding, KnowledgeEntry, Program
from .redaction import RedactionContext, Redactor

EXPORT_FORMAT = "vulns-ai-export"
EXPORT_VERSION = 1


def redaction_context(session: Session) -> RedactionContext:
    programs = [(name, handle) for name, handle in session.query(Program.name, Program.handle)]
    targets = [target for (target,) in session.query(Finding.target).filter(Finding.target != "")]
    return RedactionContext.build(programs, targets)


def exported_entries(session: Session) -> list[KnowledgeEntry]:
    return (
        session.query(KnowledgeEntry)
        .options(selectinload(KnowledgeEntry.tags), selectinload(KnowledgeEntry.related))
        .filter(KnowledgeEntry.use_for_ai.is_(True), KnowledgeEntry.is_draft.is_(False))
        .order_by(KnowledgeEntry.title, KnowledgeEntry.id)
        .all()
    )


def entry_document(entry: KnowledgeEntry, context: RedactionContext) -> dict:
    """The exported form of one entry, redacted, with LF line endings."""
    redact = Redactor(context).redact

    def clean(value: str | None) -> str:
        return redact((value or "").replace("\r\n", "\n").replace("\r", "\n"))

    return {
        "id": entry.id,
        "title": clean(entry.title),
        "bug_type": entry.bug_type,
        "severity": entry.default_severity,
        "cwe": entry.cwe,
        "cvss_score": entry.cvss_score,
        "tags": [tag for tag in entry.tag_names if tag not in context.identifying_tags],
        "technology": clean(entry.technology),
        "endpoint": clean(entry.endpoint),
        "summary": clean(entry.summary),
        "report": clean(entry.markdown).strip(),
        "remediation": clean(entry.remediation),
        "references": [clean(line.strip()) for line in entry.references.splitlines() if line.strip()],
        "related": [
            {"id": related.id, "title": clean(related.title)}
            for related in sorted(entry.related, key=lambda item: (item.title, item.id))
        ],
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }


def export_json(session: Session) -> bytes:
    context = redaction_context(session)
    documents = [entry_document(entry, context) for entry in exported_entries(session)]
    payload = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(documents),
        "vulnerabilities": documents,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def document_markdown(document: dict) -> str:
    """Render an exported document as Markdown with YAML frontmatter."""
    metadata = {
        key: document[key]
        for key in ("id", "title", "bug_type", "severity", "cwe", "cvss_score", "tags", "technology", "endpoint")
    }
    metadata["summary"] = document["summary"]
    metadata["related"] = [item["id"] for item in document["related"]]
    metadata["created_at"] = document["created_at"]
    metadata["updated_at"] = document["updated_at"]
    frontmatter = yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False, width=1000).strip()
    body = [document["report"]]
    roles = report_roles(document["report"])
    if document["remediation"] and "remediation" not in roles:
        body.append(f"## Remediation\n\n{document['remediation']}")
    if document["references"] and "references" not in roles:
        body.append("## References\n\n" + "\n".join(f"- {line}" for line in document["references"]))
    return f"---\n{frontmatter}\n---\n\n" + "\n\n".join(part for part in body if part) + "\n"


def export_markdown_zip(session: Session) -> bytes:
    context = redaction_context(session)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry in exported_entries(session):
            document = entry_document(entry, context)
            name = f"{slugify(document['title'])[:80]}-{entry.id[:8]}.md"
            info = zipfile.ZipInfo(name, date_time=entry.updated_at.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, document_markdown(document))
    return buffer.getvalue()
