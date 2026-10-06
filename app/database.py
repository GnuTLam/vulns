import json
import re
import sqlite3
from collections.abc import Iterable

from sqlalchemy import Engine, create_engine, event, func, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base, KnowledgeEntry, Tag, knowledge_relations, knowledge_tags
from .taxonomy import parse_tags

KNOWLEDGE_COLUMNS = {
    "endpoint": "VARCHAR(500) NOT NULL DEFAULT ''",
    "technology": "VARCHAR(300) NOT NULL DEFAULT ''",
    "cwe": "VARCHAR(40) NOT NULL DEFAULT ''",
    "cvss_score": "FLOAT",
    "research_notes": "TEXT NOT NULL DEFAULT ''",
    # Quick-capture draft flag; existing rows migrate as non-drafts.
    "is_draft": "BOOLEAN NOT NULL DEFAULT 0",
    "use_for_ai": "BOOLEAN NOT NULL DEFAULT 1",
}
FINDING_COLUMNS = {
    "discovered_at": "VARCHAR(30) NOT NULL DEFAULT ''",
    # Bounty record. Defaults (NULL for amounts) let ALTER TABLE add them to existing databases.
    "triaged_at": "VARCHAR(30) NOT NULL DEFAULT ''",
    "resolved_at": "VARCHAR(30) NOT NULL DEFAULT ''",
    "rewarded_at": "VARCHAR(30) NOT NULL DEFAULT ''",
    "bonus": "FLOAT",
    "currency": "VARCHAR(8) NOT NULL DEFAULT 'USD'",
    "program_severity": "VARCHAR(20) NOT NULL DEFAULT ''",
    "duplicate_of": "VARCHAR(160) NOT NULL DEFAULT ''",
}


def create_database(database_url: str) -> tuple[Engine, sessionmaker[Session]]:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)

    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def _ensure_columns(connection, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in connection.execute(text(f"PRAGMA table_info({table})"))}
    for name, definition in columns.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))


def init_database(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    if not engine.url.drivername.startswith("sqlite"):
        return
    with engine.begin() as connection:
        _ensure_columns(connection, "knowledge_entries", KNOWLEDGE_COLUMNS)
        _ensure_columns(connection, "findings", FINDING_COLUMNS)
        _migrate_json_lists(connection)
        connection.execute(text("DROP TABLE IF EXISTS knowledge_fts"))
        connection.execute(
            text("""
            CREATE VIRTUAL TABLE knowledge_fts USING fts5(
                id UNINDEXED,
                title,
                summary,
                markdown,
                bug_type,
                endpoint,
                technology,
                cwe,
                tags,
                research_notes,
                is_draft UNINDEXED,
                tokenize='unicode61 remove_diacritics 2'
            )
        """)
        )
        connection.execute(
            text("""
            INSERT INTO knowledge_fts(
                id, title, summary, markdown, bug_type, endpoint, technology, cwe, tags, research_notes, is_draft
            )
            SELECT id, title, summary, markdown, bug_type, endpoint, technology, cwe,
                   COALESCE((SELECT group_concat(tags.name, ' ') FROM knowledge_tags
                             JOIN tags ON tags.id = knowledge_tags.tag_id
                             WHERE knowledge_tags.knowledge_id = knowledge_entries.id), ''),
                   research_notes, COALESCE(is_draft, 0)
            FROM knowledge_entries
        """)
        )
        _build_entity_index(connection)


def _json_list(raw) -> list:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def _migrate_json_lists(connection) -> None:
    """Move the legacy JSON list columns into the tag and relation tables, then drop them."""
    columns = {row[1] for row in connection.execute(text("PRAGMA table_info(knowledge_entries)"))}
    legacy = [name for name in ("tags_json", "related_ids_json") if name in columns]
    if not legacy:
        return
    if sqlite3.sqlite_version_info < (3, 35, 0):
        raise RuntimeError("SQLite 3.35 or newer is required to migrate this database")
    if "tags_json" in legacy:
        for entry_id, raw in connection.execute(text("SELECT id, tags_json FROM knowledge_entries")).all():
            for name in parse_tags(item for item in _json_list(raw) if isinstance(item, str)):
                connection.execute(text("INSERT OR IGNORE INTO tags(name) VALUES (:name)"), {"name": name})
                connection.execute(
                    text(
                        "INSERT OR IGNORE INTO knowledge_tags(knowledge_id, tag_id) "
                        "SELECT :entry_id, id FROM tags WHERE name = :name"
                    ),
                    {"entry_id": entry_id, "name": name},
                )
    if "related_ids_json" in legacy:
        known = {row[0] for row in connection.execute(text("SELECT id FROM knowledge_entries"))}
        for source_id, raw in connection.execute(text("SELECT id, related_ids_json FROM knowledge_entries")).all():
            for target_id in _json_list(raw):
                if target_id in known and target_id != source_id:
                    connection.execute(
                        text("INSERT OR IGNORE INTO knowledge_relations(source_id, target_id) VALUES (:s, :t)"),
                        {"s": source_id, "t": target_id},
                    )
    for name in legacy:
        connection.execute(text(f"ALTER TABLE knowledge_entries DROP COLUMN {name}"))


# Programs and findings share one FTS table. Triggers keep it current on every write,
# including ON DELETE CASCADE.
ENTITY_INDEX_SOURCES = {
    "program": {
        "table": "programs",
        "label": "name",
        "body": (
            "COALESCE(name,'')||' '||COALESCE(platform,'')||' '||COALESCE(handle,'')"
            "||' '||COALESCE(notes,'')||' '||COALESCE(url,'')"
        ),
    },
    "finding": {
        "table": "findings",
        "label": "target",
        "body": (
            "COALESCE(target,'')||' '||COALESCE(scope,'')||' '||COALESCE(report_id,'')"
            "||' '||COALESCE(private_notes,'')||' '||COALESCE(status,'')||' '||COALESCE(duplicate_of,'')"
        ),
    },
}


def _build_entity_index(connection) -> None:
    connection.execute(text("DROP TABLE IF EXISTS entity_fts"))
    connection.execute(
        text("""
        CREATE VIRTUAL TABLE entity_fts USING fts5(
            kind UNINDEXED,
            entity_id UNINDEXED,
            label,
            body,
            tokenize='unicode61 remove_diacritics 2'
        )
    """)
    )
    for kind, source in ENTITY_INDEX_SOURCES.items():
        table, label, body = source["table"], source["label"], source["body"]
        connection.execute(
            text(
                f"INSERT INTO entity_fts(kind, entity_id, label, body) "
                f"SELECT '{kind}', id, COALESCE({label},''), {body} FROM {table}"
            )
        )
        insert = (
            f"INSERT INTO entity_fts(kind, entity_id, label, body) "
            f"VALUES ('{kind}', new.id, COALESCE(new.{label},''), "
            f"{body.replace('COALESCE(', 'COALESCE(new.')})"
        )
        delete_old = f"DELETE FROM entity_fts WHERE kind='{kind}' AND entity_id=old.id;"
        for suffix in ("ai", "au", "ad"):
            connection.execute(text(f"DROP TRIGGER IF EXISTS {table}_{suffix}_fts"))
        connection.execute(text(f"CREATE TRIGGER {table}_ai_fts AFTER INSERT ON {table} BEGIN {insert}; END"))
        connection.execute(
            text(f"CREATE TRIGGER {table}_au_fts AFTER UPDATE ON {table} BEGIN {delete_old} {insert}; END")
        )
        connection.execute(text(f"CREATE TRIGGER {table}_ad_fts AFTER DELETE ON {table} BEGIN {delete_old} END"))


# Control characters mark matches in snippets. They never occur in stored text, so a
# snippet is HTML-escaped first and the markers become <mark> afterwards.
HIGHLIGHT_OPEN = "\x02"
HIGHLIGHT_CLOSE = "\x03"


def _sqlite(session: Session) -> bool:
    return bool(session.bind and session.bind.url.drivername.startswith("sqlite"))


def fts_knowledge_matches(session: Session, expression: str, limit: int = 200) -> list[tuple[str, float, str]]:
    """Ranked ``(id, bm25_rank, raw_snippet)`` for a knowledge FTS expression.

    A lower rank is a better match. Snippets still contain highlight markers and must be escaped.
    """
    if not expression or not _sqlite(session):
        return []
    rows = session.execute(
        text(
            "SELECT id, bm25(knowledge_fts) AS rank, "
            "snippet(knowledge_fts, -1, :open, :close, '…', 14) AS excerpt "
            "FROM knowledge_fts WHERE knowledge_fts MATCH :query "
            "ORDER BY rank LIMIT :limit"
        ),
        {"query": expression, "limit": limit, "open": HIGHLIGHT_OPEN, "close": HIGHLIGHT_CLOSE},
    )
    return [(row[0], float(row[1] or 0.0), row[2] or "") for row in rows]


def fts_entity_matches(session: Session, kind: str, expression: str, limit: int = 200) -> list[tuple[str, float, str]]:
    """Ranked ``(entity_id, bm25_rank, raw_snippet)`` for programs or findings."""
    if not expression or not _sqlite(session):
        return []
    rows = session.execute(
        text(
            "SELECT entity_id, bm25(entity_fts) AS rank, "
            "snippet(entity_fts, -1, :open, :close, '…', 14) AS excerpt "
            "FROM entity_fts WHERE entity_fts MATCH :query AND kind = :kind "
            "ORDER BY rank LIMIT :limit"
        ),
        {
            "query": expression,
            "kind": kind,
            "limit": limit,
            "open": HIGHLIGHT_OPEN,
            "close": HIGHLIGHT_CLOSE,
        },
    )
    return [(row[0], float(row[1] or 0.0), row[2] or "") for row in rows]


def index_knowledge(session: Session, entry: KnowledgeEntry) -> None:
    if not _sqlite(session):
        return
    session.execute(text("DELETE FROM knowledge_fts WHERE id = :id"), {"id": entry.id})
    session.execute(
        text("""
            INSERT INTO knowledge_fts(
                id, title, summary, markdown, bug_type, endpoint, technology, cwe, tags, research_notes, is_draft
            )
            VALUES (
                :id, :title, :summary, :markdown, :bug_type, :endpoint, :technology, :cwe, :tags, :research_notes,
                :is_draft
            )
        """),
        {
            "id": entry.id,
            "title": entry.title,
            "summary": entry.summary,
            "markdown": entry.markdown,
            "bug_type": entry.bug_type,
            "endpoint": entry.endpoint,
            "technology": entry.technology,
            "cwe": entry.cwe,
            "tags": " ".join(entry.tag_names),
            "research_notes": entry.research_notes,
            "is_draft": 1 if entry.is_draft else 0,
        },
    )


def remove_knowledge_index(session: Session, entry_id: str) -> None:
    if _sqlite(session):
        session.execute(text("DELETE FROM knowledge_fts WHERE id = :id"), {"id": entry_id})


def backlink_entries(session: Session, entry_id: str) -> list[KnowledgeEntry]:
    """Entries that list ``entry_id`` as related, ordered by title."""
    if not entry_id:
        return []
    return (
        session.query(KnowledgeEntry)
        .join(knowledge_relations, knowledge_relations.c.source_id == KnowledgeEntry.id)
        .filter(knowledge_relations.c.target_id == entry_id)
        .order_by(KnowledgeEntry.title)
        .all()
    )


def backlink_ids(session: Session, entry_id: str) -> list[str]:
    """Ids of the entries returned by :func:`backlink_entries` (title-ordered)."""
    return [entry.id for entry in backlink_entries(session, entry_id)]


# Weight per candidate signal; structural matches outweigh text similarity.
CANDIDATE_WEIGHTS = {
    "cwe": 5.0,
    "bug_technology": 4.0,
    "tag": 2.0,
    "fts": 3.0,
}


def _search_bm25(session: Session, query: str, limit: int) -> list[str]:
    """Ranked FTS ids, best first."""
    tokens = re.findall(r"[\wÀ-ỹ]+", query, flags=re.UNICODE)
    if not tokens or not _sqlite(session):
        return []
    expression = " OR ".join(f'"{token.replace(chr(34), "")}"*' for token in tokens[:16])
    rows = session.execute(
        text("SELECT id FROM knowledge_fts WHERE knowledge_fts MATCH :query ORDER BY bm25(knowledge_fts) LIMIT :limit"),
        {"query": expression, "limit": limit},
    )
    return [row[0] for row in rows]


def candidate_related_ids(
    session: Session,
    *,
    current_id: str = "",
    cwe: str = "",
    bug_type: str = "",
    technology: str = "",
    title: str = "",
    summary: str = "",
    tags: Iterable[str] = (),
    limit: int = 8,
) -> list[dict]:
    """Score related-entry candidates from shared CWE, bug type plus technology, tags and text similarity.

    Each result lists the reasons it matched so the interface can explain it.
    """
    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    def bump(entry_id: str, weight: float, reason: str) -> None:
        if not entry_id or entry_id == current_id:
            return
        scores[entry_id] = scores.get(entry_id, 0.0) + weight
        bucket = reasons.setdefault(entry_id, [])
        if reason not in bucket:
            bucket.append(reason)

    cwe = (cwe or "").strip().upper()
    bug_type = (bug_type or "").strip()
    technology = (technology or "").strip()

    # Shared CWE (exact, case-insensitive).
    if cwe:
        rows = (
            session.query(KnowledgeEntry.id)
            .filter(func.upper(KnowledgeEntry.cwe) == cwe, KnowledgeEntry.id != current_id)
            .limit(200)
            .all()
        )
        for (entry_id,) in rows:
            bump(entry_id, CANDIDATE_WEIGHTS["cwe"], "cwe")

    # Shared bug type and overlapping technology.
    if bug_type and technology:
        rows = (
            session.query(KnowledgeEntry.id, KnowledgeEntry.technology)
            .filter(
                KnowledgeEntry.bug_type == bug_type,
                KnowledgeEntry.technology != "",
                KnowledgeEntry.id != current_id,
            )
            .limit(300)
            .all()
        )
        wanted = {part.strip().casefold() for part in re.split(r"[,/]", technology) if part.strip()}
        for entry_id, other_technology in rows:
            other = {part.strip().casefold() for part in re.split(r"[,/]", other_technology or "") if part.strip()}
            if wanted & other:
                bump(entry_id, CANDIDATE_WEIGHTS["bug_technology"], "bug_technology")

    # Shared tags, counting at most three per candidate.
    wanted_tags = parse_tags(tags)
    if wanted_tags:
        rows = (
            session.query(knowledge_tags.c.knowledge_id, func.count())
            .join(Tag, Tag.id == knowledge_tags.c.tag_id)
            .filter(Tag.name.in_(wanted_tags))
            .group_by(knowledge_tags.c.knowledge_id)
            .limit(300)
            .all()
        )
        for entry_id, shared in rows:
            bump(entry_id, CANDIDATE_WEIGHTS["tag"] * min(shared, 3), "tag")

    # Nearest entries by FTS5 BM25 over the free-text fields.
    free_text = " ".join(part for part in (title, summary, technology, bug_type) if part).strip()
    fts_ids = _search_bm25(session, free_text, limit=limit * 3)
    for rank, entry_id in enumerate(fts_ids):
        # Decay so the top hit contributes the full FTS weight and later hits less.
        bump(entry_id, CANDIDATE_WEIGHTS["fts"] * (1.0 - rank / max(len(fts_ids), 1) * 0.5), "fts")

    if not scores:
        return []

    # Text-only matches are weak evidence, so they must clear a higher score.
    structural = {"cwe", "bug_technology", "tag"}
    fts_only_floor = CANDIDATE_WEIGHTS["fts"] * 0.9

    def keep(entry_id: str) -> bool:
        if structural.intersection(reasons.get(entry_id, [])):
            return True
        return scores[entry_id] >= fts_only_floor

    ranked = [entry_id for entry_id in scores if keep(entry_id)]
    if not ranked:
        return []

    top_ids = sorted(ranked, key=lambda entry_id: (-scores[entry_id], entry_id))[:limit]
    entries = {entry.id: entry for entry in session.query(KnowledgeEntry).filter(KnowledgeEntry.id.in_(top_ids)).all()}
    result: list[dict] = []
    for entry_id in top_ids:
        entry = entries.get(entry_id)
        if not entry:
            continue
        result.append(
            {
                "id": entry.id,
                "title": entry.title,
                "bug_type": entry.bug_type,
                "severity": entry.default_severity,
                "cwe": entry.cwe,
                "score": round(scores[entry_id], 3),
                "reasons": reasons.get(entry_id, []),
            }
        )
    return result


def push_rediscovery_for_entry(
    session: Session,
    entry: KnowledgeEntry,
    *,
    limit: int = 5,
    exclude_ids: set[str] | None = None,
) -> list[dict]:
    """Related prior research for ``entry``, excluding ``exclude_ids``."""
    excluded = set(exclude_ids or set())
    excluded.add(entry.id)
    candidates = candidate_related_ids(
        session,
        current_id=entry.id,
        cwe=entry.cwe,
        bug_type=entry.bug_type,
        technology=entry.technology,
        title=entry.title,
        summary=entry.summary,
        tags=entry.tag_names,
        limit=limit + len(excluded),
    )
    return [item for item in candidates if item["id"] not in excluded][:limit]


def push_rediscovery_for_signals(
    session: Session,
    *,
    cwe: str = "",
    bug_type: str = "",
    technology: str = "",
    title: str = "",
    summary: str = "",
    tags: Iterable[str] = (),
    limit: int = 6,
    exclude_ids: set[str] | None = None,
) -> list[dict]:
    """Related prior research for aggregated signals, used on program pages."""
    excluded = set(exclude_ids or set())
    candidates = candidate_related_ids(
        session,
        current_id="",
        cwe=cwe,
        bug_type=bug_type,
        technology=technology,
        title=title,
        summary=summary,
        tags=tags,
        limit=limit + len(excluded),
    )
    return [item for item in candidates if item["id"] not in excluded][:limit]
