# Architecture

VulnS is a single-user, server-rendered FastAPI application backed by SQLite.

## Domain

| Entity | Purpose |
| --- | --- |
| **KnowledgeEntry** | The report of a vulnerability: title, bug type, default severity, summary, endpoint, technology, CWE, CVSS, Markdown report, remediation, references, research notes, tags, related reports and the *Use for AI* switch. |
| **Tag** | A normalised label (`jwt`, `account-takeover`) shared by reports. Unused tags are removed. |
| **Finding** | The submission of a report to one program: target, scope, status (submitted / processing / done), outcome, severity, report reference, dates, payout, bonus, currency (VND / EUR / USD), paid flag and date, and the program's own rating. |
| **Program** | A bounty program and its notes. Deleting it removes its findings; their reports stay and become unfiled. |
| **Evidence** | A file attached to a report. |

In the interface a **vulnerability** is a finding together with its report, at one URL, `/findings/{id}`. Creating one inserts both rows in a single transaction. Severity is one field: it sets the finding's severity and, while no other finding uses the report, the report's default severity. A report with no finding is *unfiled* (imported drafts, old quick captures, reports of deleted programs, agent-written research); a report used by several findings (older data, or `save_finding` with an existing `knowledge_id`) keeps working and its pages say so. Deleting a vulnerability removes its report and evidence files only when no other finding uses the report. Tags and related reports are stored in join tables (`knowledge_tags`, `knowledge_relations`), so renaming a tag or deleting a report never leaves stale references.

## Pages

| Route | Purpose |
| --- | --- |
| `/findings` | Vulnerabilities list; `?tab=bounty` is the Bounty tab (rewards ledger, paid / owed per currency, period and program) |
| `/findings/new`, `/findings/{id}/edit` | The one form: report, submission and bounty |
| `/findings/{id}` | The vulnerability: report, attachments, status and bounty cards, related and similar research |
| `/findings/{id}/status`, `/bounty`, `/paid` | Quick actions. A status change dates triage and an accepted resolution, a recorded reward dates the reward and the payment, when those dates are empty; the full form never invents dates |
| `/findings/import`, `/findings/unfiled` | Import a `.md` file into a program; list unfiled reports to file to a program or delete |
| `/programs`, `/programs/{id}` | Programs; the program explorer appears on a program's pages and forms, not on the index |
| `/tags`, `/export`, `/search` | Tag manager, AI export, lookup |
| `/knowledge/export.json`, `/knowledge/export.zip`, `/knowledge/{id}/ai.json` | Machine endpoints, unchanged |
| `/markdown/preview`, `/knowledge/candidates`, `/evidence/{id}` | Editor APIs and attachments |

## Modules

| Module | Responsibility |
| --- | --- |
| `main.py` | `create_app()`: configuration, database, middleware and routers |
| `routes/` | One router per area: auth, dashboard, search, programs, tags, AI export, editor APIs, findings (the vulnerability list with its Bounty tab, the vulnerability pages and actions), evidence, system (version, update proxy) |
| `web.py` | Shared by the routers: page rendering, database session, sign-in check, record loaders |
| `vulns.py` | Create, update, delete, duplicate and file a vulnerability (report and submission) and the quick status and bounty actions; shared by the routes and the agent API |
| `forms.py` | Parsing and validation of submitted form values |
| `stats.py` | Dashboard figures, the Bounty tab report (paid / owed per currency, period and program, with a rewards ledger) and response-time medians |
| `agent.py` | Agent tool catalogue; `/api/agent/*` (WebMCP) and `/mcp` (JSON-RPC). Write tools call the `vulns.py` service functions |
| `search.py` | Query parsing and ranked search across all record kinds |
| `database.py` | Engine setup, in-place migration, FTS5 indexes, related-entry signals |
| `update_check.py` | Release-manifest check: is a newer compatible version published? |
| `version.py` | `APP_VERSION` (build-time release tag) and `SCHEMA_VERSION` |
| `updater/` | The sidecar applying one-click updates; it alone holds the Docker socket |
| `taxonomy.py` | Severities, statuses, bug types, currencies and tag normalisation |
| `export.py` | AI export as one JSON document or a ZIP of Markdown files |
| `redaction.py` | Replaces secrets, emails, real hosts, public IPs and program names in exported text |
| `markdown_store.py` | Markdown mirror of each report with YAML frontmatter |
| `markdown_import.py` | Validation and parsing of uploaded `.md` files |
| `security.py` | Sessions, CSRF tokens, URL and filename validation |

## Storage

- SQLite holds structured data. Schema changes are ordered, run-once migrations recorded in a `schema_migrations` table; the baseline (additive columns, the legacy JSON list columns moved into their join tables, the earlier thirteen finding statuses mapped onto status, outcome and the paid flag) brings any existing database up to date in place. Currencies other than VND, EUR and USD stay on the rows that already use them.
- One-click updates ([docs/UPDATES.md](UPDATES.md)): a GitHub release manifest gates an *Update now* button on the dashboard; a sidecar with the Docker socket backs the database up (`VACUUM INTO`, verified), pulls the release image and swaps the container, gated by a deep health check with automatic rollback. The app container itself gains no privileges.
- Reports are indexed in an FTS5 table on write. Programs and findings share a second FTS5 table maintained by SQL triggers, so every write path keeps it current. Both are rebuilt at startup.
- Each report is mirrored to `data/markdown/<id>.md`. Evidence files use generated names under `data/evidence/`.
- The AI export is built on request from the database and is never written to disk. It contains only reports with *Use for AI* on that are not drafts; research notes, programs, bounty data and evidence never enter it.

## Security

- Username and password sign-in with constant-time comparison; signed, HTTP-only, SameSite session cookie.
- CSRF token on every state-changing form and on browser agent calls.
- Markdown is rendered with raw HTML disabled and sanitized with Bleach; only renderer-generated classes (table alignment, attachment links) pass. Evidence is rendered by its stored type: inline images and videos, download links for everything else, and links instead of external images. Search snippets are escaped before highlighting.
- Uploads are size-limited and stored under generated names; only raster images, audio and video are served inline.
- The AI export replaces tokens, cookies, keys, emails, real hosts and program names before any text leaves the application.
- Strict Content-Security-Policy, no third-party requests in the browser, no telemetry. The one outbound request the server makes is fetching its own release manifest from GitHub, disabled with `VULNS_UPDATE_CHECK=false`; nothing is sent beyond the request itself.

## Limits

- One administrative user configured through environment variables.
- SQLite and local file storage keep self-hosting simple; the ORM layer allows a later move to PostgreSQL.
- Search is lexical (FTS5 BM25). Embeddings and retrieval are left to the AI tool that consumes the export.
