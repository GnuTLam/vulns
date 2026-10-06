"""Runtime configuration from ``VULNS_*`` environment variables."""

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

PLACEHOLDERS = {
    "change-me",
    "replace-with-a-long-password",
    "replace-with-a-random-secret",
    "change-this-session-secret",
}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_url: str
    admin_password: str
    session_secret: str
    max_upload_bytes: int
    secure_cookies: bool
    admin_username: str = "admin"
    agent_token: str = ""

    @property
    def markdown_dir(self) -> Path:
        return self.data_dir / "markdown"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("VULNS_DATA_DIR", "./data")).resolve()
        agent_token = os.getenv("VULNS_AGENT_TOKEN", "").strip()
        if agent_token and len(agent_token) < 32:
            raise RuntimeError("VULNS_AGENT_TOKEN must be at least 32 characters")
        return cls(
            data_dir=data_dir,
            database_url=os.getenv("DATABASE_URL", f"sqlite:///{data_dir / 'vulns.db'}"),
            admin_password=_admin_password(),
            session_secret=_session_secret(data_dir),
            max_upload_bytes=int(os.getenv("VULNS_MAX_UPLOAD_MB", "50")) * 1024 * 1024,
            secure_cookies=_flag("VULNS_SECURE_COOKIES"),
            admin_username=os.getenv("VULNS_ADMIN_USERNAME", "").strip() or "admin",
            agent_token=agent_token,
        )


def _flag(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() == "true"


def _admin_password() -> str:
    password = os.getenv("VULNS_ADMIN_PASSWORD", "")
    if not password or password in PLACEHOLDERS:
        raise RuntimeError("Set VULNS_ADMIN_PASSWORD")
    if len(password) < 8 and not _flag("VULNS_ALLOW_WEAK_PASSWORD"):
        raise RuntimeError(
            "VULNS_ADMIN_PASSWORD must be at least 8 characters "
            "(set VULNS_ALLOW_WEAK_PASSWORD=true to allow a shorter one)"
        )
    return password


def _session_secret(data_dir: Path) -> str:
    """Return VULNS_SESSION_SECRET, or a random secret kept in the data directory."""
    configured = os.getenv("VULNS_SESSION_SECRET", "").strip()
    if configured:
        if configured in PLACEHOLDERS or len(configured) < 32:
            raise RuntimeError("VULNS_SESSION_SECRET must be a random value of at least 32 characters")
        return configured
    path = data_dir / ".session-secret"
    if path.exists():
        stored = path.read_text(encoding="utf-8").strip()
        if len(stored) >= 32:
            return stored
    data_dir.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48)
    path.write_text(secret, encoding="utf-8")
    path.chmod(0o600)
    return secret
