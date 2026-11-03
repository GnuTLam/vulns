"""Version reporting, the pre-update database backup and the updater proxy.

Three trust levels meet here, mirroring ``app/agent.py``'s token endpoint:

- ``/api/version``, ``/api/update/status`` and ``/api/update/run``: the signed-in user
  with the page CSRF token, like every other form action.
- ``/api/update/backup`` and ``/health/deep``: the updater sidecar, authenticated with
  the shared ``X-Updater-Token`` (a cross-site page cannot send it).
- ``/health`` (in ``auth.py``) stays public for the Docker healthcheck.

The update itself is executed by the sidecar; the app only asks it to start and relays
its progress, and produces the verified database backup it needs first.
"""

import hmac
import json
import sqlite3
import urllib.request
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from ..security import validate_csrf
from ..version import APP_VERSION, SCHEMA_VERSION
from ..web import require_auth

router = APIRouter()

BACKUP_TABLES = ("knowledge_entries", "findings", "programs", "tags")


def _require_updater(request: Request) -> None:
    """The sidecar authenticates with the shared token; nobody else may call these."""
    settings = request.app.state.settings
    expected = settings.updater_token
    if not expected:
        raise HTTPException(status_code=403, detail="updater token not configured")
    submitted = request.headers.get("X-Updater-Token", "")
    if not hmac.compare_digest(submitted.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="invalid updater token")


def _sqlite_path(request: Request) -> str:
    """Filesystem path of the SQLite database, from the configured URL."""
    settings = request.app.state.settings
    url = settings.database_url
    if not url.startswith("sqlite:///"):
        return ""
    return url[len("sqlite:///") :]


@router.get("/api/version", dependencies=[Depends(require_auth)])
def version():
    return {"version": APP_VERSION, "schema": SCHEMA_VERSION}


@router.get("/health/deep")
def health_deep(request: Request):
    """Full readiness: the updater calls this before declaring an update good."""
    _require_updater(request)
    path = _sqlite_path(request)
    if not path:
        return {"status": "ok", "database": "external"}
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in BACKUP_TABLES}
        stamped = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    finally:
        connection.close()
    problems = []
    if not integrity or integrity[0] != "ok":
        problems.append("integrity_check failed")
    if keys:
        problems.append(f"{len(keys)} foreign key violation(s)")
    if stamped != SCHEMA_VERSION:
        problems.append(f"schema at {stamped}, expected {SCHEMA_VERSION}")
    if problems:
        return JSONResponse({"status": "unhealthy", "problems": problems, "counts": counts}, status_code=503)
    return {"status": "ok", "schema": stamped, "counts": counts}


@router.post("/api/update/backup")
def create_backup(request: Request):
    """Snapshot the database with ``VACUUM INTO`` before the updater swaps containers.

    Produces a compact, transactionally consistent file while the app keeps serving.
    The integrity of the snapshot itself is verified before it is handed back.
    """
    _require_updater(request)
    path = _sqlite_path(request)
    if not path:
        return JSONResponse({"error": "only SQLite databases can be backed up here"}, status_code=400)
    backups_dir = request.app.state.settings.data_dir / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    name = f"backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.db"
    destination = backups_dir / name
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.execute("VACUUM INTO ?", (str(destination),))
    except sqlite3.OperationalError as error:
        connection.close()
        destination.unlink(missing_ok=True)
        return JSONResponse({"error": f"backup failed: {error}"}, status_code=500)
    finally:
        connection.close()
    snapshot = sqlite3.connect(f"file:{destination}?mode=ro", uri=True)
    try:
        integrity = snapshot.execute("PRAGMA integrity_check").fetchone()
    finally:
        snapshot.close()
    if not integrity or integrity[0] != "ok":
        destination.unlink(missing_ok=True)
        return JSONResponse({"error": "backup failed its integrity check"}, status_code=500)
    return {"path": name, "bytes": destination.stat().st_size, "integrity": "ok"}


def _sidecar(request: Request, method: str, path: str, body: dict | None = None, timeout: float = 3.0) -> dict:
    settings = request.app.state.settings
    url = settings.updater_url.rstrip("/") + path
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json", "X-Updater-Token": settings.updater_token}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    sidecar_request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(sidecar_request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("unexpected updater response")
    return data


@router.get("/api/update/status", dependencies=[Depends(require_auth)])
def update_status(request: Request):
    settings = request.app.state.settings
    if not settings.updater_url or not settings.updater_token:
        return {"configured": False, "reachable": False}
    try:
        state = _sidecar(request, "GET", "/status")
    except (OSError, ValueError):
        # During the container swap the app is briefly down; the browser keeps polling.
        return {"configured": True, "reachable": False}
    return {"configured": True, "reachable": True, "updater": state}


@router.post("/api/update/run", dependencies=[Depends(require_auth)])
def run_update(request: Request, csrf: str = Form(...)):
    validate_csrf(request, csrf)
    settings = request.app.state.settings
    if not settings.updater_url or not settings.updater_token:
        return JSONResponse({"error": "not_configured"}, status_code=503)
    status = request.app.state.update_checker.check()
    image = status.get("image") or ""
    if not status.get("available") or not image:
        return JSONResponse({"error": "no_update_available"}, status_code=409)
    try:
        ack = _sidecar(request, "POST", "/update", {"image": image, "version": status.get("latest")}, timeout=10)
    except (OSError, ValueError):
        return JSONResponse({"error": "updater_unreachable"}, status_code=503)
    return ack
