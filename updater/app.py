"""VulnS updater sidecar.

Applies one-click updates on behalf of the app container. The app asks this service to
update; this service owns the Docker socket, asks the app for a verified database
backup, pulls the new image, swaps the container, and verifies the result over the
app's ``/health/deep`` endpoint. Any failure after the swap rolls the previous
container back and restores the backup, so a failed update can never leave the
application unusable or the database half-migrated.

Flow of ``POST /update``::

    backup (app endpoint)  ->  pull image  ->  swap containers  ->  verify
         | failure: nothing changed.              | failure: rollback + restore backup.

State survives restarts in ``/data/backups/update-state.json``; every event is appended
to ``/data/backups/update-log.jsonl``.

Security: this process is as powerful as root on the host (Docker socket). It listens
only inside the compose network, requires the shared ``X-Updater-Token`` on every call,
and only ever pulls images under a fixed repository prefix.
"""

import hmac
import json
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import docker
from docker.errors import NotFound

TOKEN = os.getenv("VULNS_UPDATER_TOKEN", "").strip()
APP_URL = os.getenv("APP_URL", "http://vulns:8000").rstrip("/")
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "vulns")
PREVIOUS_NAME = f"{CONTAINER_NAME}-previous"
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
BACKUPS_DIR = DATA_DIR / "backups"
STATE_FILE = BACKUPS_DIR / "update-state.json"
LOG_FILE = BACKUPS_DIR / "update-log.jsonl"
PORT = int(os.getenv("PORT", "8070"))
IMAGE_PREFIX = os.getenv("IMAGE_PREFIX", "ghcr.io/gnutlam/vulns:")
HEALTH_TIMEOUT = int(os.getenv("HEALTH_TIMEOUT", "180"))
STOP_TIMEOUT = int(os.getenv("STOP_TIMEOUT", "30"))
KEEP_BACKUPS = int(os.getenv("KEEP_BACKUPS", "5"))

VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+$")

state: dict = {"phase": "idle"}
state_lock = threading.Lock()
operation_lock = threading.Lock()


def give_to_volume_owner(path: Path) -> None:
    """Make something this process created belong to the user of the data volume.

    The updater runs as root (Docker socket); the app runs as an unprivileged user. If a
    file the updater writes into the shared volume — the backups directory, a restored
    database — stayed root-owned, the app could not use it. Failures are ignored: when
    the updater does not run as root, ownership is already correct.
    """
    try:
        info = DATA_DIR.stat()
        os.chown(path, info.st_uid, info.st_gid)
    except OSError:
        pass


def log(event: str, **fields) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
    try:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # logging must never break an update


def save_state() -> None:
    try:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:
        pass


def set_phase(phase: str, **fields) -> None:
    with state_lock:
        state["phase"] = phase
        state.update(fields)
        if phase in ("done", "failed", "rolled_back", "rollback_failed"):
            state["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state()
    log("phase", phase=phase, **fields)


def container_recreate_plan(attrs: dict, image_env: list[str] | None = None) -> dict:
    """The pieces of a container's configuration that must survive a swap.

    Returns the low-level Docker API arguments (``create_container`` plus a matching
    ``create_host_config``) so the replacement container is configured exactly like the
    one it replaces — volumes, port bindings, environment, labels, healthcheck.

    A container's ``Env`` is its image's ``ENV`` merged with what compose set. ``image_env``
    is the old image's ``ENV``: those entries are left out so the new image's own values
    apply. Carrying them over would pin, for example, ``VULNS_APP_VERSION`` of the old
    release, and the updated app would keep reporting the old version.
    """
    config = attrs["Config"]
    inherited = set(image_env or ())
    host = attrs["HostConfig"]
    binds = [
        f"{mount['Source']}:{mount['Destination']}" + ("" if mount.get("RW", True) else ":ro")
        for mount in attrs.get("Mounts", [])
        if mount.get("Type") in ("volume", "bind") and mount.get("Source")
    ]
    bindings = host.get("PortBindings") or {}
    port_bindings = {
        container_port: [{"HostIp": binding[0]["HostIp"], "HostPort": binding[0]["HostPort"]}]
        for container_port, binding in bindings.items()
        if binding
    }
    restart = host.get("RestartPolicy") or {}
    healthcheck = {key: value for key, value in (config.get("Healthcheck") or {}).items() if value is not None}
    return {
        "environment": [entry for entry in config.get("Env") or [] if entry not in inherited],
        "labels": config.get("Labels") or {},
        "hostname": config.get("Hostname") or None,
        "healthcheck": healthcheck or None,
        "binds": binds or None,
        "port_bindings": port_bindings or None,
        "exposed_ports": sorted(port_bindings) or None,
        "security_opt": host.get("SecurityOpt") or None,
        "network_mode": host.get("NetworkMode") or None,
        "restart_policy": {"Name": restart["Name"]} if restart.get("Name", "no") != "no" else None,
    }


def image_env(container) -> list[str]:
    """The ``ENV`` of the image a container was created from; empty when it cannot be read."""
    try:
        return container.image.attrs["Config"].get("Env") or []
    except (KeyError, AttributeError, docker.errors.DockerException):
        return []


def recreate_container(client, attrs: dict, image: str, name: str | None = CONTAINER_NAME, old_image_env=None):
    """Create (not start) a replacement container with the captured configuration.

    ``name`` may be ``None``: the replacement is then created under an automatic name
    and takes ``CONTAINER_NAME`` only after the old container releases it.
    """
    plan = container_recreate_plan(attrs, old_image_env)
    host_config = client.api.create_host_config(
        binds=plan["binds"],
        port_bindings=plan["port_bindings"],
        restart_policy=plan["restart_policy"],
        security_opt=plan["security_opt"],
        network_mode=plan["network_mode"],
    )
    return client.api.create_container(
        image,
        name=name,
        environment=plan["environment"],
        labels=plan["labels"],
        hostname=plan["hostname"],
        ports=plan["exposed_ports"],
        healthcheck=plan["healthcheck"],
        host_config=host_config,
    )


def app_request(path: str, method: str, timeout: float = 15.0) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{APP_URL}{path}", method=method, headers={"X-Updater-Token": TOKEN, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")[:500]
        return error.code, {"error": body}
    except (OSError, ValueError) as error:
        return 0, {"error": str(error)}


def app_backup() -> str:
    """Ask the running app for a verified snapshot; returns the backup file name."""
    status, payload = app_request("/api/update/backup", "POST", timeout=120.0)
    if status != 200 or "path" not in payload:
        raise RuntimeError(f"backup refused by the app: {payload.get('error', status)}")
    return payload["path"]


def app_healthy(deadline: float) -> bool:
    while time.monotonic() < deadline:
        status, _payload = app_request("/health/deep", "GET", timeout=10.0)
        if status == 200:
            return True
        time.sleep(3)
    return False


def restore_backup(backup_name: str) -> None:
    """Copy a backup over the live database; call only while no container has it open."""
    source = BACKUPS_DIR / backup_name
    if not source.exists():
        raise RuntimeError(f"backup {backup_name} not found")
    database = DATA_DIR / "vulns.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(database) + suffix).unlink(missing_ok=True)
    shutil.copyfile(source, database)
    give_to_volume_owner(database)
    with database.open("rb") as handle:
        os.fsync(handle.fileno())


def prune_backups() -> None:
    backups = sorted(BACKUPS_DIR.glob("backup-*.db"), key=lambda path: path.name, reverse=True)
    for stale in backups[KEEP_BACKUPS:]:
        stale.unlink(missing_ok=True)


def run_update(image: str, version: str) -> None:
    client = docker.from_env()
    backup_name = ""
    swapped = False
    try:
        set_phase("backup")
        backup_name = app_backup()

        set_phase("pull", image=image)
        client.images.pull(image)
        log("pulled", image=image)

        set_phase("swap")
        current = client.containers.get(CONTAINER_NAME)
        old_image = current.image.tags[0] if current.image.tags else current.attrs["Config"]["Image"]
        # Remove a leftover previous container so this one can take the name.
        try:
            client.containers.get(PREVIOUS_NAME).remove(force=True)
        except NotFound:
            pass
        # Create the replacement (not started) under a temporary name while the old
        # container still serves; rename, stop and start give the shortest possible gap.
        replacement = recreate_container(client, current.attrs, image, name=None, old_image_env=image_env(current))
        current.rename(PREVIOUS_NAME)
        replacement_container = client.containers.get(replacement["Id"])
        replacement_container.rename(CONTAINER_NAME)
        current.stop(timeout=STOP_TIMEOUT)
        client.api.start(replacement["Id"])
        swapped = True

        set_phase("verify", version=version)
        deadline = time.monotonic() + HEALTH_TIMEOUT
        healthy = False
        while time.monotonic() < deadline:
            try:
                if client.containers.get(CONTAINER_NAME).status == "exited":
                    break
            except NotFound:
                break
            if app_healthy(time.monotonic() + 15):
                healthy = True
                break
        if not healthy:
            raise RuntimeError("the new container did not become healthy")

        # Success: the old container and old backups are no longer needed.
        try:
            client.containers.get(PREVIOUS_NAME).remove(force=True)
        except NotFound:
            pass
        prune_backups()
        set_phase("done", to=version, image=image, from_image=old_image, backup=backup_name)
        log("updated", to=version, image=image, from_image=old_image, backup=backup_name)
    except Exception as error:  # noqa: BLE001 - every failure must be classified below
        log("update_failed", error=str(error))
        if swapped:
            run_rollback(client, reason=f"update failed: {error}", backup_name=backup_name)
        else:
            set_phase("failed", error=str(error))


def run_rollback(client, reason: str, backup_name: str = "") -> None:
    """Restore the previous container; on failure leave a clear, actionable state."""
    try:
        set_phase("rolling_back", reason=reason)
        try:
            current = client.containers.get(CONTAINER_NAME)
        except NotFound:
            current = None
        try:
            previous = client.containers.get(PREVIOUS_NAME)
        except NotFound:
            previous = None

        if previous is not None:
            # Fast path: the pre-update container still exists, stopped since the swap.
            if current is not None:
                current.stop(timeout=STOP_TIMEOUT)
                current.remove(force=True)
            previous.rename(CONTAINER_NAME)
        elif current is not None and state.get("from_image"):
            # Explicit rollback after a successful update: recreate from the old image.
            client.images.pull(state["from_image"])
            replacement = recreate_container(
                client, current.attrs, state["from_image"], old_image_env=image_env(current)
            )
            current.stop(timeout=STOP_TIMEOUT)
            current.remove(force=True)
            client.api.start(replacement["Id"])
            previous = client.containers.get(CONTAINER_NAME)
        else:
            raise RuntimeError("no previous container or image to roll back to")

        # The database is restored while nothing has it open, then the old app starts.
        if not backup_name:
            backups = sorted(BACKUPS_DIR.glob("backup-*.db"), key=lambda path: path.name, reverse=True)
            backup_name = backups[0].name if backups else ""
        if backup_name:
            restore_backup(backup_name)

        previous.start()
        if app_healthy(time.monotonic() + HEALTH_TIMEOUT):
            set_phase("rolled_back", reason=reason, backup=backup_name)
            log("rolled_back", reason=reason, backup=backup_name)
        else:
            set_phase("rollback_failed", reason=reason, backup=backup_name)
            log("rollback_failed", reason=reason, backup=backup_name)
    except Exception as error:  # noqa: BLE001
        set_phase("rollback_failed", error=str(error), reason=reason)
        log("rollback_failed", error=str(error), reason=reason)


class Handler(BaseHTTPRequestHandler):
    server_version = "vulns-updater"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not TOKEN:
            return False
        submitted = self.headers.get("X-Updater-Token", "")
        return hmac.compare_digest(submitted.encode(), TOKEN.encode())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def do_GET(self):  # noqa: N802 - http.server naming
        if not self._authorized():
            self._send(403, {"error": "invalid updater token"})
            return
        if self.path != "/status":
            self._send(404, {"error": "not found"})
            return
        with state_lock:
            payload = dict(state)
        payload["busy"] = payload.get("phase") in ("backup", "pull", "swap", "verify", "rolling_back")
        payload["rollback_available"] = bool(payload.get("from_image")) and not payload["busy"]
        self._send(200, payload)

    def do_POST(self):  # noqa: N802 - http.server naming
        if not self._authorized():
            self._send(403, {"error": "invalid updater token"})
            return
        body = self._body()

        if self.path == "/update":
            image = str(body.get("image", ""))
            version = str(body.get("version", ""))
            if not image.startswith(IMAGE_PREFIX) or not VERSION_RE.match(version):
                self._send(400, {"error": "image or version not allowed"})
                return
            if not operation_lock.acquire(blocking=False):
                self._send(409, {"error": "an update or rollback is already running"})
                return
            threading.Thread(target=self._run_locked, args=(run_update, image, version), daemon=True).start()
            self._send(202, {"started": True, "to": version})
            return

        if self.path == "/rollback":
            if not operation_lock.acquire(blocking=False):
                self._send(409, {"error": "an update or rollback is already running"})
                return
            threading.Thread(
                target=self._run_locked,
                args=(lambda: run_rollback(docker.from_env(), reason="requested by the user"),),
                daemon=True,
            ).start()
            self._send(202, {"started": True})
            return

        self._send(404, {"error": "not found"})

    @staticmethod
    def _run_locked(function, *args) -> None:
        try:
            function(*args)
        finally:
            operation_lock.release()

    def log_message(self, format, *args):  # noqa: A002 - http.server signature
        log("http", request=format % args)


def main() -> None:
    if len(TOKEN) < 32:
        raise SystemExit("VULNS_UPDATER_TOKEN must be set to at least 32 characters")
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    give_to_volume_owner(BACKUPS_DIR)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("started", container=CONTAINER_NAME, app=APP_URL)
    server.serve_forever()


if __name__ == "__main__":
    main()
