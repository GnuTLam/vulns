# VulnS

A self-hosted workspace for bug bounty hunters. VulnS keeps each vulnerability in one place: the Markdown report and its submission to a program, tracked from discovery to payout.

## Features

- **One vulnerability, one page.** A vulnerability is a Markdown report (GitHub-style tables, task lists, strikethrough; bug type, severity, CWE, CVSS, endpoint, technology and free tags) together with its submission to one program. One form, *New vulnerability*, is reachable from every page and saves both; the vulnerability then lives at `/findings/{id}`.
- **Vulnerabilities list.** Filter by search, program, status or severity; each row shows severity, status, outcome and bounty, and opens the vulnerability.
- **Submission tracking.** Status (*Submitted*, *Processing*, *Done*) and outcome (accepted, duplicate, informative, rejected, out of scope), report IDs, discovery, triage and reward dates, payouts and bonuses in VND, EUR or USD, whether the money has been received, and program re-ratings. The vulnerability page changes status or records a reward in one step and dates the change itself.
- **Unfiled reports.** Reports without a program (imported drafts, old quick captures, the reports of deleted programs) are listed at `/findings/unfiled`, linked from the vulnerabilities page, each with a *File to program* action.
- **Tags.** Normalised labels such as `jwt` or `account-takeover`, with suggestions while typing and a page (*Data → Tags*) to rename, merge or delete them; a tag opens the vulnerabilities that carry it.
- **Dashboard.** What is waiting on a program, accepted reports still unpaid, drafts to finish, earnings and response-time medians.
- **Bounty tab.** On the vulnerabilities page: paid and still-owed rewards per currency, by month or year, program and severity, with a ledger of every reward and a one-click *Mark paid*. Currencies are never added together.
- **Search.** One ranked, diacritic-insensitive query language across vulnerabilities, unfiled reports and programs, with a `Ctrl K` palette.
- **Evidence.** Screenshots, videos, HTTP traces and other files attached to a report. Inserted into a report, images and videos play inline and other files become download links.
- **Portable data.** Every report is also written as UTF-8 Markdown with YAML frontmatter; `.md` files can be imported into a program.
- **Export for AI.** Every vulnerability marked *Use for AI* as one JSON file or a ZIP of Markdown files, with tokens, cookies, emails, real hosts and program names replaced.
- **Agent API.** Seven tools exposed over WebMCP in the browser and over MCP for external clients.
- **One-click updates.** When a new release is published, the dashboard offers an *Update now* button that backs up the database, swaps the container and verifies the result — rolling back automatically if anything fails. See [docs/UPDATES.md](docs/UPDATES.md).

## Quick start

Requires Docker with Compose.

```bash
cp .env.example .env          # then set VULNS_ADMIN_PASSWORD
docker compose up -d --build
```

To enable one-click updates, also set `VULNS_UPDATER_TOKEN` in `.env` (any random value
of 32+ characters). Release images are pulled from ghcr.io; the button appears on the
dashboard whenever a newer compatible release exists.

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
| `VULNS_UPDATER_TOKEN` | empty | Shared secret for one-click updates (32+ characters); empty disables the Update button |
| `VULNS_UPDATE_CHECK` | `true` | Check GitHub for a newer release and offer the update |
| `VULNS_VERSION` | `latest` | Image tag to run; the updater sets this when you update in-app |
| `VULNS_PORT` | `8000` | Host port published by Docker Compose |

## Local development

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
VULNS_ADMIN_PASSWORD=dev-password uvicorn app.main:create_app --factory --reload
```

Run the linter with `ruff check .`.

## Search syntax

| Query | Meaning |
| --- | --- |
| `oauth redirect` | every word must match; prefix and diacritic-insensitive |
| `"open redirect"` | exact phrase |
| `-csrf` | exclude a word |
| `sev:critical` `status:processing` `type:xss` | severity, status (`submitted`, `processing`, `done`), bug type |
| `outcome:duplicate` | the program's decision: `accepted`, `duplicate`, `informative`, `rejected`, `out_of_scope` |
| `tag:jwt` `cwe:352` `tech:graphql` | tag and taxonomy |
| `endpoint:/oauth` `target:api` | location |
| `program:acme` `currency:VND` | program name, payout currency |
| `cvss:>=8` `payout:>500` | numeric comparisons (`>`, `>=`, `<`, `<=`, `=`) |
| `after:2026-01-01` `before:2026-07-01` | last-updated bounds |
| `is:open` `is:processing` `is:done` `is:accepted` `is:draft` `is:ai` | lifecycle and AI-export predicates |
| `is:rewarded` `is:paid` `is:unpaid` `is:downgraded` | bounty predicates; `is:unpaid` is a recorded bounty not yet received |
| `has:tags` `has:poc` `has:evidence` `has:reward` | presence checks |
| `kind:program` | restrict to one record kind |

Filters combine, and any filter can be negated with `-` (for example `-status:draft`). Unknown fields are reported and searched as plain text.

## Export for AI

**Data → AI export** (`/export`) lists what is included, excluded and still a draft, and downloads the vulnerability database for an AI pipeline:

- `/knowledge/export.json`: one JSON document with every exported vulnerability (taxonomy, tags, summary, report, remediation, references, related reports).
- `/knowledge/export.zip`: the same reports as Markdown files with YAML frontmatter.

A report is exported when *Use for AI* is on and it is not a draft; turn the switch off for confidential or undisclosed reports. Research notes, programs, bounty data and evidence files are never exported.

Before export, VulnS replaces tokens, cookies, keys, emails, public IP addresses, program names (`[program]`) and hosts found in URLs, `Host` headers or finding targets (`target-1.example`). Internal addresses, payloads and links to public advisories are kept. A bare domain name in prose is replaced only when it matches a finding target, so check *Preview AI export* in the *More* menu of a vulnerability before sharing an export.

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
| `markdown/` | one Markdown file per report |
| `evidence/` | uploaded files |
| `backups/` | pre-update database snapshots and the update log |
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
  vulns.py           create, update, delete, duplicate and file vulnerabilities, shared with the agent
  forms.py           form parsing and validation
  stats.py           dashboard and Bounty tab figures
  agent.py           agent tools, WebMCP and MCP endpoints
  search.py          query language and ranked search
  database.py        schema migration, FTS5 index and relation signals
  update_check.py    release manifest check for in-app updates
  version.py         app and schema version of the running build
  export.py          AI export as JSON or Markdown
  redaction.py       secret and identifier redaction for the export
  markdown_*.py      Markdown files and import
  templates/         Jinja templates
  static/            CSS, JavaScript and icons
updater/             the sidecar that applies one-click updates
docs/                architecture, agent API, updates and UI guidelines
```
