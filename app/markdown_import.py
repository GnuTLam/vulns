import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from markdown_it import MarkdownIt

from .taxonomy import parse_tags

MARKDOWN_PARSER = MarkdownIt("commonmark", {"html": False})
FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*(?:\n|\Z)", re.DOTALL)
STRUCTURAL_TOKENS = {
    "heading_open",
    "fence",
    "code_block",
    "bullet_list_open",
    "ordered_list_open",
    "blockquote_open",
    "hr",
}
INLINE_MARKUP_TOKENS = {"em_open", "strong_open", "code_inline", "link_open", "image"}


class MarkdownImportError(ValueError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class ImportedMarkdown:
    title: str
    markdown: str
    bug_type: str
    default_severity: str
    summary: str
    endpoint: str
    technology: str
    cwe: str
    cvss_score: float | None
    research_notes: str
    remediation: str
    references: str
    tags: list[str]
    use_for_ai: bool


REFERENCES_LIMIT = 20_000


def _metadata_text(metadata: dict[str, Any], key: str, limit: int | None = None) -> str:
    value = metadata.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value[:limit] if limit else value


def _first_heading(tokens) -> str:
    for index, token in enumerate(tokens[:-1]):
        if token.type == "heading_open" and tokens[index + 1].type == "inline":
            return tokens[index + 1].content.strip()
    return ""


def _has_real_markdown(tokens) -> bool:
    has_content = any(
        (token.type == "inline" and token.content.strip())
        or (token.type in {"fence", "code_block"} and token.content.strip())
        for token in tokens
    )
    if not has_content:
        return False
    if any(token.type in STRUCTURAL_TOKENS for token in tokens):
        return True
    return any(child.type in INLINE_MARKUP_TOKENS for token in tokens for child in (token.children or []))


def _cvss(metadata: dict[str, Any]) -> float | None:
    value = metadata.get("cvss_score")
    if value in (None, ""):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None


def _tags(metadata: dict[str, Any]) -> list[str]:
    value = metadata.get("tags")
    if isinstance(value, str):
        return parse_tags(value)
    if isinstance(value, list):
        return parse_tags(item for item in value if isinstance(item, str))
    return []


def _references(metadata: dict[str, Any]) -> str:
    value = metadata.get("references", "")
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        # Scalars only: str() of a nested, aliased structure can expand enormously.
        items = (str(item).strip() for item in value if isinstance(item, (str, int, float)))
        return "\n".join(item for item in items if item)[:REFERENCES_LIMIT]
    return ""


def _has_yaml_alias(source: str) -> bool:
    """Reject YAML anchors and aliases (VulnS never writes them) to block alias bombs."""
    return any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(source, Loader=yaml.SafeLoader))


def parse_markdown_upload(
    filename: str,
    payload: bytes,
    *,
    bug_types: tuple[str, ...],
    severities: tuple[str, ...],
) -> ImportedMarkdown:
    """Validate an uploaded .md file and extract knowledge fields.

    The extension alone is not trusted: the content must be UTF-8 text with real
    Markdown structure. YAML frontmatter is optional.
    """
    if Path(filename or "").suffix.casefold() != ".md":
        raise MarkdownImportError("Only .md files can be imported", status_code=415)
    if not payload:
        raise MarkdownImportError("The Markdown file is empty")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MarkdownImportError("The Markdown file must use UTF-8 encoding", status_code=415) from exc
    if "\x00" in text or any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        raise MarkdownImportError("The uploaded file contains binary or unsupported control data", status_code=415)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    metadata: dict[str, Any] = {}
    body = text
    if text.startswith("---\n"):
        match = FRONTMATTER_RE.match(text)
        if not match:
            raise MarkdownImportError("The YAML frontmatter is not closed correctly")
        try:
            if _has_yaml_alias(match.group(1)):
                raise MarkdownImportError("YAML anchors and aliases are not supported in frontmatter")
            loaded = yaml.safe_load(match.group(1))
        except yaml.YAMLError as exc:
            raise MarkdownImportError("The YAML frontmatter is invalid") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise MarkdownImportError("The YAML frontmatter must be a key-value mapping")
        metadata = loaded or {}
        body = text[match.end() :]

    body = body.strip()
    tokens = MARKDOWN_PARSER.parse(body)
    if not _has_real_markdown(tokens):
        raise MarkdownImportError("The file does not contain recognizable Markdown structure")

    fallback_title = Path(filename).stem.replace("-", " ").replace("_", " ").strip()
    title = (_metadata_text(metadata, "title") or _first_heading(tokens) or fallback_title or "Imported Markdown")[:240]
    bug_type = _metadata_text(metadata, "bug_type", 100)
    severity = _metadata_text(metadata, "severity", 20).casefold()
    return ImportedMarkdown(
        title=title,
        markdown=f"{body}\n",
        bug_type=bug_type if bug_type in bug_types else "Other",
        default_severity=severity if severity in severities else "medium",
        summary=_metadata_text(metadata, "summary", 1200),
        endpoint=_metadata_text(metadata, "endpoint", 500),
        technology=_metadata_text(metadata, "technology", 300),
        cwe=_metadata_text(metadata, "cwe", 40).upper(),
        cvss_score=_cvss(metadata),
        research_notes=_metadata_text(metadata, "research_notes"),
        remediation=_metadata_text(metadata, "remediation"),
        references=_references(metadata),
        tags=_tags(metadata),
        use_for_ai=metadata.get("use_for_ai") is not False,
    )
