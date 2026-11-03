"""In-app updates: version comparison, the release check, the backup endpoint, the
dashboard banner and the migration baseline. Network access is never needed: the
checker has a test seam and everything else is exercised through the TestClient."""

import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.update_check import evaluate, parse_version
from app.version import SCHEMA_VERSION

UPDATER_TOKEN = "updater-token-that-is-long-enough-32"


def make_settings(tmp_path: Path, **extra) -> Settings:
    values = dict(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        admin_password="mật-khẩu-thử-nghiệm",
        session_secret="test-session-secret-that-is-long-enough",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
        updater_token=UPDATER_TOKEN,
        update_check_enabled=True,
    )
    values.update(extra)
    return Settings(**values)


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


@pytest.fixture
def client(tmp_path: Path):
    application = create_app(make_settings(tmp_path))
    with TestClient(application, follow_redirects=False) as test_client:
        login = test_client.get("/login")
        response = test_client.post(
            "/login",
            data={"username": "admin", "password": "mật-khẩu-thử-nghiệm", "csrf": csrf_of(login.text)},
        )
        assert response.status_code == 303
        yield test_client, application


AVAILABLE = {
    "available": True,
    "reason": "newer",
    "latest": "9.9.9",
    "image": "ghcr.io/gnutlam/vulns:9.9.9",
    "notes_url": "https://example.com/notes",
}


def test_parse_version():
    assert parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("v0.10.0") == (0, 10, 0)
    assert parse_version("dev") is None
    assert parse_version("") is None
    assert parse_version("1.2") is None


def test_evaluate_orders_versions():
    same = {"version": "1.0.0", "image": "x:1.0.0"}
    assert evaluate("1.0.0", 1, same)["reason"] == "current"
    assert evaluate("1.0.0", 1, {"version": "1.1.0", "image": "x:1.1.0"})["available"] is True
    # A release that needs a newer baseline than this build is not offered.
    blocked = {"version": "2.0.0", "min_updatable_from": "1.5.0", "min_schema": 1}
    assert evaluate("1.0.0", 1, blocked)["reason"] == "blocked_version"
    schema_blocked = {"version": "2.0.0", "min_updatable_from": "0.2.0", "min_schema": 4}
    assert evaluate("1.0.0", 1, schema_blocked)["reason"] == "blocked_schema"
    # Dev builds and missing manifests never show an update.
    assert evaluate("dev", 1, {"version": "2.0.0"})["reason"] == "unknown"
    assert evaluate("1.0.0", 1, None)["reason"] == "unknown"


def test_check_never_blocks_on_a_stalled_network():
    # A black-holed address: the connection never answers, so the fetch must be abandoned
    # at the timeout and reported as unknown rather than delaying the dashboard render.
    from app.update_check import UpdateChecker

    checker = UpdateChecker(url="http://10.255.255.1/release.json", timeout=0.2)
    started = time.monotonic()
    result = checker.check("1.0.0", 1)
    assert time.monotonic() - started < 3
    assert result["available"] is False
    assert result["reason"] == "unknown"


def test_settings_defaults_keep_existing_fixtures_valid():
    # Every test in the suite constructs Settings without the update fields.
    settings = Settings(
        data_dir=Path("/tmp/x"),
        database_url="sqlite:////tmp/x/test.db",
        admin_password="password-123",
        session_secret="session-secret-that-is-long-enough-here",
        max_upload_bytes=1,
        secure_cookies=False,
    )
    assert settings.update_check_enabled is False
    assert settings.updater_url == ""
    assert settings.updater_token == ""


def test_api_version(client):
    test_client, _app = client
    response = test_client.get("/api/version")
    assert response.status_code == 200
    assert response.json() == {"version": "dev", "schema": SCHEMA_VERSION}


def test_health_deep_requires_updater_token(client):
    test_client, _app = client
    assert test_client.get("/health/deep").status_code == 403
    assert test_client.get("/health/deep", headers={"X-Updater-Token": "wrong"}).status_code == 403
    response = test_client.get("/health/deep", headers={"X-Updater-Token": UPDATER_TOKEN})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["schema"] == SCHEMA_VERSION


def test_backup_creates_a_readable_snapshot(client, tmp_path: Path):
    test_client, _app = client
    connection = sqlite3.connect(tmp_path / "test.db")
    connection.execute("INSERT INTO tags(name) VALUES ('account-takeover')")
    connection.commit()
    connection.close()

    assert test_client.post("/api/update/backup").status_code == 403
    response = test_client.post("/api/update/backup", headers={"X-Updater-Token": UPDATER_TOKEN})
    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity"] == "ok"

    snapshot = sqlite3.connect(f"file:{tmp_path / 'backups' / payload['path']}?mode=ro", uri=True)
    names = [row[0] for row in snapshot.execute("SELECT name FROM tags")]
    snapshot.close()
    assert names == ["account-takeover"]


def test_update_run_checks_csrf_and_configuration(client):
    test_client, app = client
    home = test_client.get("/")
    token = csrf_of(home.text)
    # A missing or wrong CSRF token is rejected before anything else happens.
    assert test_client.post("/api/update/run", data={"csrf": "wrong"}).status_code == 403
    # Without an updater URL the endpoint reports that one-click updates are off.
    object.__setattr__(app.state.settings, "updater_url", "")
    response = test_client.post("/api/update/run", data={"csrf": token})
    assert response.status_code == 503
    assert response.json()["error"] == "not_configured"


def test_update_run_reports_unreachable_updater(client):
    test_client, app = client
    object.__setattr__(app.state.settings, "updater_url", "http://127.0.0.1:9")
    app.state.update_checker.override = AVAILABLE
    token = csrf_of(test_client.get("/").text)
    response = test_client.post("/api/update/run", data={"csrf": token})
    assert response.status_code == 503
    assert response.json()["error"] == "updater_unreachable"


def test_update_status_reports_unreachable_updater(client):
    test_client, app = client
    object.__setattr__(app.state.settings, "updater_url", "http://127.0.0.1:9")
    response = test_client.get("/api/update/status")
    assert response.status_code == 200
    assert response.json() == {"configured": True, "reachable": False}


def test_dashboard_banner_only_for_available_updates(client):
    test_client, app = client
    app.state.update_checker.override = AVAILABLE
    html = test_client.get("/").text
    assert "data-update-banner" in html
    assert "9.9.9" in html
    assert "data-update-start" in html

    app.state.update_checker.override = {"available": False, "reason": "current", "latest": "1.0.0"}
    assert "data-update-banner" not in test_client.get("/").text


def test_dashboard_banner_hidden_when_check_disabled(tmp_path: Path):
    settings = make_settings(tmp_path, update_check_enabled=False)
    application = create_app(settings)
    with TestClient(application, follow_redirects=False) as test_client:
        login = test_client.get("/login")
        test_client.post(
            "/login",
            data={"username": "admin", "password": "mật-khẩu-thử-nghiệm", "csrf": csrf_of(login.text)},
        )
        application.state.update_checker.override = AVAILABLE
        assert "data-update-banner" not in test_client.get("/").text


def legacy_database(path: Path) -> None:
    """A database from before the migration registry: tags still a JSON column,
    endpoint/technology/... missing, no schema_migrations table."""
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE knowledge_entries (
            id VARCHAR(36) PRIMARY KEY,
            title VARCHAR(300) NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            markdown TEXT NOT NULL DEFAULT '',
            bug_type VARCHAR(120) NOT NULL DEFAULT '',
            default_severity VARCHAR(20) NOT NULL DEFAULT 'medium',
            tags_json TEXT,
            created_at DATETIME,
            updated_at DATETIME
        );
        INSERT INTO knowledge_entries (id, title, tags_json)
        VALUES ('entry-1', 'OAuth account takeover', '["jwt", "account-takeover"]');
        """
    )
    connection.commit()
    connection.close()


def test_baseline_migration_preserves_legacy_data(tmp_path: Path):
    database = tmp_path / "legacy.db"
    legacy_database(database)
    create_app(make_settings(tmp_path, database_url=f"sqlite:///{database}"))

    connection = sqlite3.connect(database)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(knowledge_entries)")}
    assert {"endpoint", "technology", "cwe", "is_draft", "use_for_ai"} <= columns
    assert "tags_json" not in columns
    assert connection.execute("SELECT title FROM knowledge_entries").fetchone()[0] == "OAuth account takeover"
    tags = sorted(row[0] for row in connection.execute("SELECT name FROM tags"))
    assert tags == ["account-takeover", "jwt"]
    stamped = connection.execute("SELECT version, description FROM schema_migrations").fetchall()
    connection.close()
    assert stamped == [(1, "baseline columns and legacy JSON lists")]


def test_migrations_run_once_and_startup_is_idempotent(tmp_path: Path):
    settings = make_settings(tmp_path)
    create_app(settings)
    create_app(settings)  # second startup must not re-apply or duplicate anything
    connection = sqlite3.connect(tmp_path / "test.db")
    stamps = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    connection.close()
    assert stamps == 1
