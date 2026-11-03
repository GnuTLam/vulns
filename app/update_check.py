"""Release manifest check: is a newer, compatible version published?

The manifest is a small ``release.json`` attached to every GitHub Release, downloaded from
``releases/latest/download/release.json`` (a CDN redirect, no API token, no rate limit).
The comparison logic is pure and unit-tested; only :meth:`UpdateChecker.check` touches
the network, with a short timeout and a TTL cache so dashboard renders never block on it
more than once per interval. Failures are silent: the banner simply does not appear.
"""

import json
import re
import threading
import time
import urllib.request

from .version import APP_VERSION, SCHEMA_VERSION

RELEASE_MANIFEST_URL = "https://github.com/GnuTLam/vulns/releases/latest/download/release.json"
CHECK_INTERVAL_SECONDS = 6 * 60 * 60
FAILURE_INTERVAL_SECONDS = 15 * 60
FETCH_TIMEOUT_SECONDS = 3.0

_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse_version(value: str) -> tuple[int, int, int] | None:
    """``"1.2.3"`` or ``"v1.2.3"`` → ``(1, 2, 3)``; anything else (including ``dev``) → ``None``."""
    match = _VERSION.match((value or "").strip())
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def evaluate(current_version: str, current_schema: int, manifest: dict | None) -> dict:
    """Compare the running build against a release manifest.

    The result always has the same shape so callers never branch on errors:

    - ``available``: a strictly newer release exists and the current build can upgrade to
      it (``current >= min_updatable_from`` and ``current_schema >= min_schema``).
    - ``reason``: ``current``, ``newer``, ``blocked_version``, ``blocked_schema`` or
      ``unknown`` (no or unparsable manifest, or a non-release build such as ``dev``).
    """
    current = parse_version(current_version)
    latest = parse_version(str((manifest or {}).get("version", "")))
    if not current or not latest:
        return {"available": False, "reason": "unknown", "latest": (manifest or {}).get("version", "")}
    if latest <= current:
        return {"available": False, "reason": "current", "latest": manifest.get("version")}
    minimum = parse_version(str(manifest.get("min_updatable_from", "")))
    if minimum and current < minimum:
        return {"available": False, "reason": "blocked_version", "latest": manifest.get("version")}
    min_schema = manifest.get("min_schema")
    if isinstance(min_schema, int) and current_schema < min_schema:
        return {"available": False, "reason": "blocked_schema", "latest": manifest.get("version")}
    return {
        "available": True,
        "reason": "newer",
        "latest": manifest.get("version"),
        "image": manifest.get("image", ""),
        "notes_url": manifest.get("notes_url", ""),
    }


class UpdateChecker:
    """Cached manifest check. One instance lives on ``app.state``."""

    def __init__(self, url: str = RELEASE_MANIFEST_URL, timeout: float = FETCH_TIMEOUT_SECONDS):
        self.url = url
        self.timeout = timeout
        self._fetched_at = 0.0
        self._interval = CHECK_INTERVAL_SECONDS
        self._result: dict | None = None
        # Test seam: when set, returned instead of any network call.
        self.override: dict | None = None

    def _fetch(self) -> dict | None:
        request = urllib.request.Request(self.url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            manifest = json.loads(response.read().decode("utf-8"))
        return manifest if isinstance(manifest, dict) else None

    def _fetch_bounded(self) -> dict | None:
        """Fetch on a worker thread and wait at most the timeout.

        A socket timeout does not bound DNS resolution, and a stalled resolver must never
        delay a page render. The worker is a daemon, so one stuck in name resolution is
        simply abandoned until the next interval.
        """
        box: dict = {}
        done = threading.Event()

        def worker():
            try:
                box["manifest"] = self._fetch()
            except (OSError, ValueError):
                box["manifest"] = None
            finally:
                done.set()

        threading.Thread(target=worker, daemon=True).start()
        if not done.wait(self.timeout + 0.5):
            return None
        return box.get("manifest")

    def check(self, current_version: str = APP_VERSION, current_schema: int = SCHEMA_VERSION) -> dict:
        """The cached evaluation for the running build; refreshes after the interval."""
        if self.override is not None:
            return dict(self.override)
        if self._result is None or time.monotonic() - self._fetched_at > self._interval:
            manifest = self._fetch_bounded()
            if manifest is None:
                self._interval = FAILURE_INTERVAL_SECONDS
            else:
                self._interval = CHECK_INTERVAL_SECONDS
            self._result = evaluate(current_version, current_schema, manifest)
            self._fetched_at = time.monotonic()
        return dict(self._result)


def update_banner(request) -> dict | None:
    """Values for the dashboard banner, or ``None`` when no update should be offered.

    Used by the dashboard route only, so the check never runs on other pages.
    """
    settings = request.app.state.settings
    if not settings.update_check_enabled:
        return None
    status = request.app.state.update_checker.check()
    if not status.get("available") or not status.get("image"):
        return None
    return {"latest": status["latest"], "image": status["image"], "notes_url": status.get("notes_url", "")}
