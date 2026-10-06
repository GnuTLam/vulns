"""Agent API over WebMCP (session and CSRF) and MCP (bearer token)."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agent import TOOLS
from app.config import Settings
from app.main import create_app

AGENT_TOKEN = "agent-token-for-tests-0123456789abcdef"


@pytest.fixture
def agent(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'agent.db'}",
        admin_password="agent-password",
        session_secret="agent-test-session-secret-at-least-32-characters",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
        agent_token=AGENT_TOKEN,
    )
    app = create_app(settings)
    with TestClient(app, follow_redirects=False) as client:
        login = client.get("/login")
        token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
        assert (
            client.post("/login", data={"username": "admin", "password": "agent-password", "csrf": token}).status_code
            == 303
        )
        csrf = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/").text).group(1)

        def call(tool: str, **arguments):
            response = client.post(
                "/api/agent/call", json={"tool": tool, "arguments": arguments}, headers={"X-CSRF-Token": csrf}
            )
            return response.status_code, response.json()

        yield client, call, tmp_path


def rpc(client: TestClient, method: str, params: dict | None = None, *, token: str = AGENT_TOKEN, rpc_id: int = 1):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_catalogue_is_small_and_closed():
    names = [tool["name"] for tool in TOOLS]
    assert names == [
        "get_overview",
        "search",
        "get_record",
        "save_program",
        "save_knowledge",
        "save_finding",
        "delete_record",
    ]
    for tool in TOOLS:
        assert tool["inputSchema"]["additionalProperties"] is False
        assert 40 < len(tool["description"]) < 900


def test_full_workflow_through_the_session_transport(agent):
    _client, call, data_dir = agent
    status, created = call("save_program", name="Acme", platform="HackerOne")
    assert status == 200 and created["created"]
    program_id = created["program"]["id"]

    status, saved = call(
        "save_knowledge",
        title="OAuth redirect abuse",
        bug_type="OAuth / SSO",
        severity="high",
        summary="Open redirect leaks codes.",
        markdown="# Summary\n\nLeak.\n\n## Steps to reproduce\n\n1. Go\n\n## Proof of concept\n\n```http\nGET /\n```\n",
    )
    assert status == 200, saved
    knowledge_id = saved["knowledge"]["id"]
    assert saved["knowledge"]["in_ai_export"] is True
    assert (data_dir / "markdown" / f"{knowledge_id}.md").exists()

    status, linked = call(
        "save_finding",
        program_id=program_id,
        knowledge_id=knowledge_id,
        status="submitted",
        submitted_at="2026-09-01",
        target="api.acme.example",
    )
    assert status == 200, linked
    finding = linked["finding"]
    assert finding["severity"] == "high"  # inherited from the research when not given

    status, paid = call(
        "save_finding",
        id=finding["id"],
        status="paid",
        triaged_at="2026-09-03",
        rewarded_at="2026-09-20",
        payout=1500,
        currency="USD",
    )
    assert status == 200, paid
    assert paid["finding"]["total_reward"] == 1500
    assert paid["finding"]["target"] == "api.acme.example"  # untouched field survives a partial update

    status, overview = call("get_overview")
    assert overview["counts"]["findings"] == 1
    assert overview["earnings"] == [{"currency": "USD", "amount": 1500.0}]
    assert overview["median_days_to_triage"] == 2

    status, found = call("search", query="oauth", kind="knowledge")
    assert [row["id"] for row in found["results"]] == [knowledge_id]
    status, listed = call("search", kind="program")
    assert listed["total"] == 1 and listed["results"][0]["title"] == "Acme"

    status, record = call("get_record", kind="program", id=program_id)
    assert record["findings"][0]["id"] == finding["id"]

    status, deleted = call("delete_record", kind="finding", id=finding["id"], confirm=True)
    assert status == 200 and deleted["deleted"]["kind"] == "finding"
    status, after = call("get_record", kind="knowledge", id=knowledge_id)
    assert after["findings"] == []


def test_partial_knowledge_update_keeps_other_fields_and_draft_state(agent):
    _client, call, _data_dir = agent
    _status, imported = call(
        "save_knowledge",
        source_markdown=(
            "---\ntitle: Imported SSRF\nbug_type: SSRF\nseverity: critical\ncwe: CWE-918\n---\n"
            "# Summary\n\nFetches internal.\n"
        ),
    )
    entry = imported["knowledge"]
    assert entry["draft"] is True and entry["cwe"] == "CWE-918" and entry["bug_type"] == "SSRF"

    _status, edited = call("save_knowledge", id=entry["id"], summary="Renderer fetches metadata.")
    assert edited["knowledge"]["summary"] == "Renderer fetches metadata."
    assert edited["knowledge"]["cwe"] == "CWE-918"
    assert edited["knowledge"]["draft"] is True  # an agent edit is not a triage decision

    _status, promoted = call("save_knowledge", id=entry["id"], draft=False)
    assert promoted["knowledge"]["draft"] is False


def test_agent_manages_tags_and_the_ai_flag(agent):
    _client, call, _data_dir = agent
    _status, saved = call(
        "save_knowledge", title="JWT none", bug_type="Authentication", severity="critical", tags=["JWT", "Auth Bypass"]
    )
    entry = saved["knowledge"]
    assert entry["tags"] == ["auth-bypass", "jwt"] and entry["in_ai_export"] is True

    _status, updated = call("save_knowledge", id=entry["id"], use_for_ai=False)
    assert updated["knowledge"]["tags"] == ["auth-bypass", "jwt"]
    assert updated["knowledge"]["in_ai_export"] is False

    _status, found = call("search", query="tag:jwt")
    assert [row["tags"] for row in found["results"]] == [["auth-bypass", "jwt"]]
    _status, overview = call("get_overview")
    assert overview["ai_export"]["excluded_by_owner"] == 1


def test_agent_mistakes_return_actionable_errors(agent):
    _client, call, _data_dir = agent
    status, body = call("save_program", name="X", colour="red")
    assert status == 400 and "Unknown field" in body["error"] and "Allowed" in body["error"]
    status, body = call("save_finding", program_id="nope")
    assert status == 400 and "knowledge_id" in body["error"]
    status, body = call("get_record", kind="knowledge", id="missing")
    assert status == 400 and "search" in body["error"]
    status, body = call("delete_record", kind="program", id="x", confirm=False)
    assert status == 400 and "confirm" in body["error"]
    status, body = call("search", query="x", limit=500)
    assert status == 400 and "limit" in body["error"]
    call("save_program", name="Dup")
    status, body = call("save_program", name="dup")
    assert status == 400 and body["status"] == 409


def test_session_writes_require_the_csrf_header(agent):
    client, _call, _data_dir = agent
    response = client.post("/api/agent/call", json={"tool": "get_overview", "arguments": {}})
    assert response.status_code == 403


def test_cross_origin_browser_calls_are_refused(agent):
    client, _call, _data_dir = agent
    response = client.get("/api/agent/tools", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_mcp_transport_lists_and_calls_tools_with_a_bearer_token(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'mcp.db'}",
        admin_password="agent-password",
        session_secret="agent-test-session-secret-at-least-32-characters",
        max_upload_bytes=1024,
        secure_cookies=False,
        agent_token=AGENT_TOKEN,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        init = rpc(
            client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}
        )
        assert init.json()["result"]["serverInfo"]["name"] == "vulns"
        assert "instructions" in init.json()["result"]
        assert (
            client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            ).status_code
            == 202
        )
        tools = rpc(client, "tools/list").json()["result"]["tools"]
        assert len(tools) == 7

        response = rpc(client, "tools/call", {"name": "save_program", "arguments": {"name": "Bearer Co"}})
        created = response.json()["result"]
        assert created["isError"] is False
        assert created["structuredContent"]["program"]["name"] == "Bearer Co"
        # Bearer calls are stateless: no session cookie is minted for them.
        assert "set-cookie" not in response.headers

        failed = rpc(client, "tools/call", {"name": "get_record", "arguments": {}}).json()["result"]
        assert failed["isError"] is True

        assert rpc(client, "tools/list", token="wrong-token-wrong-token-wrong-token").status_code == 401
        assert rpc(client, "nope").json()["error"]["code"] == -32601


def test_mcp_is_unavailable_without_a_configured_token(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'none.db'}",
        admin_password="agent-password",
        session_secret="agent-test-session-secret-at-least-32-characters",
        max_upload_bytes=1024,
        secure_cookies=False,
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        assert rpc(client, "tools/list", token="").status_code == 401


def test_weak_password_needs_an_explicit_opt_in(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VULNS_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("VULNS_SESSION_SECRET", "s" * 40)
    monkeypatch.delenv("VULNS_ALLOW_WEAK_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        Settings.from_env()
    monkeypatch.setenv("VULNS_ALLOW_WEAK_PASSWORD", "true")
    assert Settings.from_env().admin_password == "admin"


def test_login_requires_the_username(agent):
    client, _call, _data_dir = agent
    client.post(
        "/logout", data={"csrf": re.search(r'name="csrf-token" content="([^"]+)"', client.get("/").text).group(1)}
    )
    login = client.get("/login")
    token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
    wrong = client.post("/login", data={"username": "root", "password": "agent-password", "csrf": token})
    assert wrong.status_code == 401 and "Incorrect username or password" in wrong.text
