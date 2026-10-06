# VulnS

A self-hosted workspace for bug bounty hunters. VulnS keeps reusable vulnerability research separate from program-specific submissions, so one write-up can be linked to many programs and every submission is tracked from discovery to payout.

## Features

- **Vulnerability database.** Each vulnerability is written once as Markdown with taxonomy (bug type, severity, CWE, CVSS, endpoint, technology) and free tags, then linked to any number of programs.
- **Tags.** Normalised labels such as `jwt` or `account-takeover`, with suggestions while typing and a page to rename, merge or delete them.
- **Submission tracking.** Per-program status, report IDs, discovery, triage and reward dates, payouts and bonuses per currency, and program re-ratings.
- **Dashboard.** What is waiting on a program, accepted reports still unpaid, drafts to finish, earnings and response-time medians.
- **Search.** One ranked, diacritic-insensitive query language across research, findings and programs, with a `Ctrl K` palette.
- **Evidence.** Screenshots, videos, HTTP traces and other files attached to research.
- **Portable data.** Every entry is also written as UTF-8 Markdown with YAML frontmatter; `.md` files can be imported back.
- **Export for AI.** Every vulnerability marked *Use for AI* as one JSON file or a ZIP of Markdown files, with tokens, cookies, emails, real hosts and program names replaced.
- **Agent API.** Seven tools exposed over WebMCP in the browser and over MCP for external clients.

## Quick start

Requires Docker with Compose.

```bash
cp .env.example .env          # then set VULNS_ADMIN_PASSWORD
docker compose up -d --build
```

Open <http://127.0.0.1:8000> and sign in as `admin` with the password from `.env`.

The service binds to localhost. To reach it from another machine, put it behind an HTTPS reverse proxy and set `VULNS_SECURE_COOKIES=true`.

## Configuration

All settings are environment variables, read from `.env` by Docker Compose.

| Variable | Default | Description |
| --- | --- | --- |
| `VULNS_ADMIN_PASSWORD` | required | Sign-in password, at least 8 characters |
| `VULNS_ADMIN_USERNAME` | `admin` | Sign-in username |
| `VULNS_ALLOW_WEAK_PASSWORD` | `false` | Allow a password shorter than 8 characters |
| `VULNS_SESSION_SECRET` | generated | Cookie signing key; generated on first start and kept in the data volume |
| `VULNS_SECURE_COOKIES` | `false` | Send the session cookie over HTTPS only |
| `VULNS_MAX_UPLOAD_MB` | `50` | Maximum size per uploaded file |
| `VULNS_AGENT_TOKEN` | empty | Bearer token for the MCP endpoint (32+ characters); empty disables it |
| `VULNS_PORT` | `8000` | Host port published by Docker Compose |

## Local development

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
VULNS_ADMIN_PASSWORD=dev-password uvicorn app.main:create_app --factory --reload
```

Run the tests with `pytest` and the linter with `ruff check .`.

## Search syntax

| Query | Meaning |
| --- | --- |
| `oauth redirect` | every word must match; prefix and diacritic-insensitive |
| `"open redirect"` | exact phrase |
| `-csrf` | exclude a word |
| `sev:critical` `status:accepted` `type:xss` | severity, lifecycle status, bug type |
| `tag:jwt` `cwe:352` `tech:graphql` | tag and taxonomy |
| `endpoint:/oauth` `target:api` | location |
| `program:acme` `currency:USD` | program name, payout currency |
| `cvss:>=8` `payout:>500` | numeric comparisons (`>`, `>=`, `<`, `<=`, `=`) |
| `after:2026-01-01` `before:2026-07-01` | last-updated bounds |
| `is:open` `is:draft` `is:ai` `is:rewarded` `is:downgraded` | lifecycle and AI-export predicates |
| `has:tags` `has:poc` `has:evidence` `has:reward` | presence checks |
| `kind:program` | restrict to one record kind |

Filters combine, and any filter can be negated with `-` (for example `-status:draft`). Unknown fields are reported and searched as plain text.

## Export for AI

**Knowledge → Export for AI** downloads the vulnerability database for an AI pipeline:

- `/knowledge/export.json`: one JSON document with every exported vulnerability (taxonomy, tags, summary, report, remediation, references, related entries).
- `/knowledge/export.zip`: the same entries as Markdown files with YAML frontmatter.

An entry is exported when *Use for AI* is on and it is not a draft; turn the switch off for confidential or undisclosed reports. Research notes, programs, bounty data and evidence files are never exported.

Before export, VulnS replaces tokens, cookies, keys, emails, public IP addresses, program names (`[program]`) and hosts found in URLs, `Host` headers or finding targets (`target-1.example`). Internal addresses, payloads and links to public advisories are kept. A bare domain name in prose is replaced only when it matches a finding target, so check the preview linked from each entry page before sharing an export.

## Agent API

AI agents can read statistics, search, and create, update or delete records through seven tools:

- **In the browser:** the tools are registered with WebMCP (`document.modelContext`) and act as the signed-in user.
- **External clients:** use the MCP endpoint at `POST /mcp` with `Authorization: Bearer $VULNS_AGENT_TOKEN`.

```bash
claude mcp add --transport http vulns http://127.0.0.1:8000/mcp --header "Authorization: Bearer <token>"
```

See [docs/AGENT_API.md](docs/AGENT_API.md).

## Data and backups

Everything lives in the `vulns_data` volume (`/data` in the container):

| Path | Content |
| --- | --- |
| `vulns.db` | SQLite database |
| `markdown/` | one Markdown file per knowledge entry |
| `evidence/` | uploaded files |
| `.session-secret` | generated session secret, when none is configured |

Back up the whole directory while the container is running:

```bash
docker compose cp vulns:/data ./vulns-backup
```

## Project layout

```
app/
  main.py            application factory
  routes/            page and form routes, one module per area
  web.py             rendering, sessions and record loading shared by the routes
  forms.py           form parsing and validation
  stats.py           dashboard figures
  agent.py           agent tools, WebMCP and MCP endpoints
  search.py          query language and ranked search
  database.py        schema migration, FTS5 index and relation signals
  export.py          AI export as JSON or Markdown
  redaction.py       secret and identifier redaction for the export
  markdown_*.py      Markdown files and import
  templates/         Jinja templates
  static/            CSS, JavaScript and icons
tests/               pytest suite
docs/                architecture, agent API and UI guidelines
```
