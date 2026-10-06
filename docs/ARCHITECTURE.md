# Architecture

VulnS is a single-user, server-rendered FastAPI application backed by SQLite.

## Domain

| Entity | Purpose |
| --- | --- |
| **KnowledgeEntry** | One vulnerability: title, bug type, default severity, summary, endpoint, technology, CWE, CVSS, Markdown report, remediation, references, research notes, tags, related entries and the *Use for AI* switch. |
| **Tag** | A normalised label (`jwt`, `account-takeover`) shared by knowledge entries. Unused tags are removed. |
| **Finding** | One knowledge entry submitted to one program: target, scope, lifecycle status, severity, report reference, dates, payout, bonus, currency and the program's own rating. |
| **Program** | A bounty program and its notes. Deleting it removes its findings but keeps all knowledge. |
| **Evidence** | A file attached to a knowledge entry. |

A knowledge entry can be linked to many programs without being copied. Tags and related entries are stored in join tables (`knowledge_tags`, `knowledge_relations`), so renaming a tag or deleting an entry never leaves stale references.

## Modules

| Module | Responsibility |
| --- | --- |
| `main.py` | `create_app()`: configuration, database, middleware and routers |
| `routes/` | One router per area: auth, dashboard, search, programs, knowledge, tags, AI export, findings, evidence |
| `web.py` | Shared by the routers: page rendering, database session, sign-in check, record loaders |
| `forms.py` | Parsing and validation of submitted form values |
| `stats.py` | Dashboard figures, earnings per currency and response-time medians |
| `agent.py` | Agent tool catalogue; `/api/agent/*` (WebMCP) and `/mcp` (JSON-RPC). Write tools call the form routes |
| `search.py` | Query parsing and ranked search across all record kinds |
| `database.py` | Engine setup, in-place migration, FTS5 indexes, related-entry signals |
| `taxonomy.py` | Severities, statuses, bug types, currencies and tag normalisation |
| `export.py` | AI export as one JSON document or a ZIP of Markdown files |
| `redaction.py` | Replaces secrets, emails, real hosts, public IPs and program names in exported text |
| `markdown_store.py` | Markdown mirror of each entry with YAML frontmatter |
| `markdown_import.py` | Validation and parsing of uploaded `.md` files |
| `security.py` | Sessions, CSRF tokens, URL and filename validation |

## Storage

- SQLite holds structured data. Columns added after the first release are created with `ALTER TABLE` at startup, and tags and related entries stored by older versions as JSON columns are moved into their join tables, so existing databases migrate in place.
- Knowledge entries are indexed in an FTS5 table on write. Programs and findings share a second FTS5 table maintained by SQL triggers, so every write path keeps it current. Both are rebuilt at startup.
- Each knowledge entry is mirrored to `data/markdown/<id>.md`. Evidence files use generated names under `data/evidence/`.
- The AI export is built on request from the database and is never written to disk. It contains only entries with *Use for AI* on that are not drafts; research notes, programs, bounty data and evidence never enter it.

## Security

- Username and password sign-in with constant-time comparison; signed, HTTP-only, SameSite session cookie.
- CSRF token on every state-changing form and on browser agent calls.
- Markdown is rendered with raw HTML disabled and sanitized with Bleach; search snippets are escaped before highlighting.
- Uploads are size-limited and stored under generated names; only raster images, audio and video are served inline.
- The AI export replaces tokens, cookies, keys, emails, real hosts and program names before any text leaves the application.
- Strict Content-Security-Policy, no third-party requests, no telemetry.

## Limits

- One administrative user configured through environment variables.
- SQLite and local file storage keep self-hosting simple; the ORM layer allows a later move to PostgreSQL.
- Search is lexical (FTS5 BM25). Embeddings and retrieval are left to the AI tool that consumes the export.
