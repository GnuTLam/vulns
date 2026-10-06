import hmac
import re
import secrets
from pathlib import Path

from fastapi import HTTPException, Request


def authenticated(request: Request) -> bool:
    return request.session.get("authenticated") is True


def password_matches(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, submitted: str) -> None:
    # Set by the agent API after verifying a bearer token, which a cross-site page cannot send.
    if getattr(request.state, "csrf_exempt", False):
        return
    expected = request.session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(submitted, expected):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def safe_filename(filename: str) -> str:
    name = Path(filename or "evidence").name
    name = re.sub(r"[^\w. -]", "_", name, flags=re.UNICODE).strip(". ")
    return name[:180] or "evidence"


def validate_external_url(value: str, field: str = "URL") -> str:
    from urllib.parse import urlsplit

    clean = value.strip()
    if not clean:
        return ""
    parsed = urlsplit(clean)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail=f"{field} must be an absolute http:// or https:// URL")
    return clean
