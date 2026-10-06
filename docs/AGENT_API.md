# Agent API

VulnS exposes one tool catalogue to AI agents over two transports:

| Transport | For | Endpoint | Authentication |
| --- | --- | --- | --- |
| WebMCP | an agent running in the browser tab | registered by `app.js` on `document.modelContext` | signed-in session plus `X-CSRF-Token` |
| MCP over HTTP | Claude Code, Claude Desktop, scripts | `POST /mcp` (JSON-RPC 2.0) | `Authorization: Bearer $VULNS_AGENT_TOKEN` |

Write tools call the same route handlers as the web forms, so validation, tag normalisation, Markdown files and search indexing behave exactly as they do for a manual edit.

## Tools

| Tool | Purpose | Main input |
| --- | --- | --- |
| `get_overview` | Dashboard figures: counts, needs-attention queue, earnings per currency, response medians, breakdowns, AI export counts | none |
| `search` | Find records with the search query language; an empty `query` with a `kind` lists the newest records | `query`, `kind`, `limit` (max 50), `offset` |
| `get_record` | Every field of one record, including its links | `kind`, `id` |
| `save_program` | Create a program, or update one when `id` is given | `name`, `platform`, `url`, `handle`, `notes`, `archived` |
| `save_knowledge` | Create or update research; `source_markdown` imports a whole `.md` document as a draft | `title`, `bug_type`, `severity`, `markdown`, `tags`, `use_for_ai`, `draft`, `related_ids` |
| `save_finding` | Link research to a program or update the submission; changing `program_id` moves it | `program_id`, `knowledge_id`, `status`, dates, `payout`, `bonus`, `currency` |
| `delete_record` | Permanently delete a program, knowledge entry, finding or evidence file | `kind`, `id`, `confirm: true` |

Behaviour common to all tools:

- Updates are partial: only the fields sent are changed. `tags` and `related_ids` replace the whole list when sent.
- Unknown fields and invalid values are rejected with a message that names the problem.
- Every returned record includes its `id` and a `link` to the page in VulnS.
- Evidence files are listed and can be deleted, but uploading one is a browser action.

The catalogue is deliberately small. Prefer adding a parameter to an existing tool over adding a new one; `tests/test_agent_api.py` pins the tool list.

## Connecting an MCP client

Set `VULNS_AGENT_TOKEN` (32+ characters) in `.env` and restart, then:

```bash
claude mcp add --transport http vulns http://127.0.0.1:8000/mcp --header "Authorization: Bearer <token>"
```

A raw request:

```bash
curl -s http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer $VULNS_AGENT_TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_overview","arguments":{}}}'
```

Without a configured token, `/mcp` rejects every request. Browser access through WebMCP is unaffected.

## WebMCP

On every signed-in page, `app.js` loads `/api/agent/tools` and registers each tool with `document.modelContext.registerTool()`, falling back to the earlier `navigator.modelContext` API. Browsers without WebMCP skip this step. Tools are unregistered when the page unloads.

## Security

- Browser calls must be same-origin, and writes must carry the page's CSRF token.
- Bearer calls skip the CSRF check (a cross-site page cannot send the header) and never create a session.
- Requests with a foreign `Origin` header are rejected with `403`.
- `research_notes` and `private_notes` are returned to agents but never included in the AI export.
