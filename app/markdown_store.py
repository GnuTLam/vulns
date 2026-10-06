import re
from pathlib import Path

import yaml

from .models import KnowledgeEntry

HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
# Heading keywords per report section, checked in order; the first match wins.
SECTION_ROLES = (
    ("summary", ("summary", "overview", "description", "root cause")),
    ("reproduction", ("steps to reproduce", "reproduction", "reproduce", "steps")),
    ("poc", ("proof of concept", "poc", "payload", "request", "response", "exploit")),
    ("impact", ("impact", "risk", "consequence")),
    ("remediation", ("remediation", "mitigation", "fix", "recommendation")),
    ("environment", ("environment", "prerequisite", "requirements", "setup")),
    ("references", ("references", "reference", "resources")),
)


def report_roles(markdown: str | None) -> set[str]:
    """Sections the Markdown report already has, so pages do not repeat a structured field."""
    roles: set[str] = set()
    in_fence = False
    for line in (markdown or "").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        match = None if in_fence else HEADING.match(line)
        if not match:
            continue
        heading = re.sub(r"[^a-z0-9]+", " ", match.group(1).casefold()).strip()
        role = next((name for name, aliases in SECTION_ROLES if any(alias in heading for alias in aliases)), None)
        if role:
            roles.add(role)
    return roles


def slugify(value: str) -> str:
    value = value.casefold().strip()
    value = re.sub(r"[^\w\s-]", "", value, flags=re.UNICODE)
    value = re.sub(r"[-\s]+", "-", value).strip("-")
    return value[:180] or "vulnerability"


def unique_slug(session, title: str, current_id: str | None = None) -> str:
    base = slugify(title)
    candidate = base
    counter = 2
    while True:
        existing = session.query(KnowledgeEntry).filter(KnowledgeEntry.slug == candidate).first()
        if not existing or existing.id == current_id:
            return candidate
        candidate = f"{base}-{counter}"
        counter += 1


def markdown_path(markdown_dir: Path, entry: KnowledgeEntry) -> Path:
    return markdown_dir / f"{entry.id}.md"


def sync_markdown(markdown_dir: Path, entry: KnowledgeEntry, session=None) -> Path:
    markdown_dir.mkdir(parents=True, exist_ok=True)
    programs = sorted(
        [
            {
                "id": finding.program.id,
                "name": finding.program.name,
                "status": finding.status,
                "target": finding.target,
                # Bounty facts are exported so the Markdown file is a complete record.
                "currency": finding.currency,
                "payout": finding.payout,
                "bonus": finding.bonus,
                "total_reward": finding.total_reward,
                "submitted_at": finding.submitted_at,
                "triaged_at": finding.triaged_at,
                "rewarded_at": finding.rewarded_at,
                "resolved_at": finding.resolved_at,
                "program_severity": finding.program_severity,
                "duplicate_of": finding.duplicate_of,
            }
            for finding in entry.findings
            if finding.program
        ],
        key=lambda item: item["name"].casefold(),
    )
    # Backlinks are only written when a session is available to look them up.
    referenced_by: list[str] = []
    if session is not None:
        from .database import backlink_ids

        referenced_by = backlink_ids(session, entry.id)
    metadata = {
        "id": entry.id,
        "slug": entry.slug,
        "title": entry.title,
        "bug_type": entry.bug_type,
        "severity": entry.default_severity,
        "tags": entry.tag_names,
        "summary": entry.summary,
        "endpoint": entry.endpoint,
        "technology": entry.technology,
        "cwe": entry.cwe,
        "cvss_score": entry.cvss_score,
        "is_draft": bool(entry.is_draft),
        "use_for_ai": bool(entry.use_for_ai),
        "research_notes": entry.research_notes,
        "related_vulnerabilities": entry.related_ids,
        "referenced_by": referenced_by,
        "remediation": entry.remediation,
        "references": [line.strip() for line in entry.references.splitlines() if line.strip()],
        "program_uses": programs,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
        "schema_version": 4,
    }
    frontmatter = yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False, width=1000).strip()
    body = entry.markdown.replace("\r\n", "\n").rstrip()
    content = f"---\n{frontmatter}\n---\n\n{body}\n"
    destination = markdown_path(markdown_dir, entry)
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(destination)
    return destination


def delete_markdown(markdown_dir: Path, entry: KnowledgeEntry) -> None:
    path = markdown_path(markdown_dir, entry)
    if path.exists():
        path.unlink()
