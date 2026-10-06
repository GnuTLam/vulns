"""Remove secrets and identifying details from report text before it is exported for AI use.

Only text leaving VulnS is redacted; stored records are never modified. Each exported
entry gets its own ``Redactor`` so a host or email keeps the same placeholder throughout
that entry (``target-1.example``, ``user1@example.com``).

Hosts are replaced where they can be recognised without guessing: in URLs, in ``Host``
headers, and when they match a finding target stored in VulnS. Bare domains elsewhere
in prose are left alone, because telling ``api.acme.com`` from ``document.cookie`` is
not possible without a domain list.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .taxonomy import normalize_tag

REDACTED = "[REDACTED]"
PROGRAM_PLACEHOLDER = "[program]"

PLACEHOLDER_HOSTS = {"localhost", "example.com", "example.org", "example.net"}
PLACEHOLDER_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local", ".internal")
# Public reference sites keep their names so links to advisories stay useful.
PUBLIC_DOMAINS = (
    "owasp.org",
    "mitre.org",
    "nist.gov",
    "cisa.gov",
    "first.org",
    "portswigger.net",
    "mozilla.org",
    "ietf.org",
    "rfc-editor.org",
    "w3.org",
    "whatwg.org",
    "github.com",
    "githubusercontent.com",
    "python.org",
    "nodejs.org",
    "php.net",
)

HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
JWT = re.compile(r"\b(eyJ[A-Za-z0-9_-]{5,})\.(eyJ[A-Za-z0-9_-]{5,})\.([A-Za-z0-9_-]*)")
VENDOR_TOKEN = re.compile(
    r"\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}"
    r"|github_pat_[A-Za-z0-9_]{40,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|[rs]k_live_[0-9A-Za-z]{16,})\b"
)
AUTH_HEADER = re.compile(
    r"(?im)^([ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*)(?:(basic|bearer|digest|negotiate|token|apikey)[ \t]+)?\S.*$"
)
SECRET_HEADER = re.compile(
    r"(?im)^([ \t]*(?:x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token"
    r"|x-amz-security-token|x-goog-api-key)[ \t]*:[ \t]*)\S.*$"
)
COOKIE_HEADER = re.compile(r"(?im)^([ \t]*(?:set-)?cookie[ \t]*:[ \t]*)(.+)$")
COOKIE_ATTRIBUTES = {"expires", "max-age", "path", "samesite", "secure", "httponly", "priority", "partitioned"}
SECRET_NAMES = (
    r"access_token|refresh_token|id_token|auth_token|session_token|token|api_key|apikey|api-key|client_secret"
    r"|secret|password|passwd|pwd|passphrase|otp|session|sessionid|session_id|sid|jsessionid|phpsessid"
    r"|csrf_token|csrftoken|xsrf_token|_csrf|authenticity_token|private_key"
)
KEY_VALUE = re.compile(r"(?i)([\"']?)\b(" + SECRET_NAMES + r")\1(\s*[:=]\s*)([\"']?)([^\"'\s&,;}<>]+)")
HARMLESS_VALUES = {"null", "none", "true", "false", "undefined", "redacted"}
URL = re.compile(r"(?i)\b((?:https?|wss?|ftp)://)(?:([^\s/@?#\"'<>]+)@)?(\[[0-9a-f:.]+\]|[a-z0-9.-]+)")
HOST_HEADER = re.compile(
    r"(?im)^([ \t]*(?:host|x-forwarded-host|x-original-host)[ \t]*:[ \t]*)(\[[0-9a-f:.]+\]|[a-z0-9.-]+)"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")


@dataclass(frozen=True)
class RedactionContext:
    """Identifiers known from the database: program names, handles and target hosts."""

    program_names: tuple[str, ...] = ()
    known_hosts: tuple[str, ...] = ()
    identifying_tags: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def build(cls, programs: list[tuple[str, str]], targets: list[str]) -> RedactionContext:
        """``programs`` holds (name, handle) pairs; ``targets`` holds finding targets."""
        names = {value.strip() for pair in programs for value in pair if value and len(value.strip()) >= 4}
        hosts = {host for value in targets if (host := host_of(value))}
        return cls(
            program_names=tuple(sorted(names, key=len, reverse=True)),
            known_hosts=tuple(sorted(hosts, key=len, reverse=True)),
            identifying_tags=frozenset(normalize_tag(name) for name in names),
        )


def host_of(value: str) -> str:
    """Host part of a URL or of a bare ``host/path`` target, or "" when there is none."""
    value = (value or "").strip()
    if not value or " " in value:
        return ""
    candidate = urlsplit(value).hostname if "://" in value else value.split("/", 1)[0].split(":", 1)[0]
    candidate = (candidate or "").lower().strip(".")
    return candidate if HOSTNAME.match(candidate) else ""


class Redactor:
    def __init__(self, context: RedactionContext | None = None):
        self.context = context or RedactionContext()
        self.hosts: dict[str, str] = {}
        self.addresses: dict[str, str] = {}
        self.emails: dict[str, str] = {}
        self._known_host = (
            re.compile(
                r"(?<![A-Za-z0-9.-])("
                + "|".join(re.escape(host) for host in self.context.known_hosts)
                + r")(?![A-Za-z0-9-])",
                re.I,
            )
            if self.context.known_hosts
            else None
        )
        self._program = (
            re.compile(r"(?<!\w)(" + "|".join(re.escape(name) for name in self.context.program_names) + r")(?!\w)")
            if self.context.program_names
            else None
        )

    def redact(self, text: str | None) -> str:
        if not text:
            return ""
        text = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
        text = JWT.sub(self._jwt, text)
        text = VENDOR_TOKEN.sub(REDACTED, text)
        text = AUTH_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2) + ' ' if m.group(2) else ''}{REDACTED}", text)
        text = SECRET_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
        text = COOKIE_HEADER.sub(self._cookie_header, text)
        text = KEY_VALUE.sub(self._key_value, text)
        text = URL.sub(self._url, text)
        text = HOST_HEADER.sub(lambda m: f"{m.group(1)}{self.host(m.group(2))}", text)
        text = EMAIL.sub(self._email, text)
        if self._known_host:
            text = self._known_host.sub(lambda m: self.host(m.group(1)), text)
        if self._program:
            text = self._program.sub(PROGRAM_PLACEHOLDER, text)
        return text

    def host(self, host: str) -> str:
        bare = host.strip("[]").lower().strip(".")
        try:
            address = ipaddress.ip_address(bare)
        except ValueError:
            address = None
        if address is not None:
            if not address.is_global:
                return host
            number = self.addresses.setdefault(bare, str(len(self.addresses) + 1))
            # Documentation ranges (RFC 5737 and RFC 3849) keep the address shape.
            return f"[2001:db8::{number}]" if address.version == 6 else f"192.0.2.{number}"
        if self._keep(bare):
            return host
        return self.hosts.setdefault(bare, f"target-{len(self.hosts) + 1}.example")

    @staticmethod
    def _keep(host: str) -> bool:
        if "." not in host or host in PLACEHOLDER_HOSTS or host.endswith(PLACEHOLDER_SUFFIXES):
            return True
        return any(host == domain or host.endswith("." + domain) for domain in PUBLIC_DOMAINS)

    @staticmethod
    def _jwt(match: re.Match) -> str:
        # The header names the algorithm, which matters for JWT findings; the claims may identify a user.
        return f"{match.group(1)}.{REDACTED}.{REDACTED if match.group(3) else ''}"

    def _url(self, match: re.Match) -> str:
        userinfo = f"{REDACTED}@" if match.group(2) else ""
        host = match.group(3)
        stripped = host.rstrip(".")
        return f"{match.group(1)}{userinfo}{self.host(stripped)}{host[len(stripped) :]}"

    def _email(self, match: re.Match) -> str:
        address = match.group(0)
        if self._keep(match.group(1).lower()):
            return address
        return self.emails.setdefault(address.lower(), f"user{len(self.emails) + 1}@example.com")

    def _cookie_header(self, match: re.Match) -> str:
        parts = []
        for part in match.group(2).split(";"):
            name, separator, value = part.partition("=")
            key = name.strip().lower()
            if not separator or key in COOKIE_ATTRIBUTES:
                parts.append(part)
            elif key == "domain":
                parts.append(f"{name}={self.host(value.strip())}")
            else:
                # Short values such as role=admin carry the finding; long ones are session material.
                parts.append(f"{name}={REDACTED}" if len(value.strip()) >= 12 else part)
        return match.group(1) + ";".join(parts)

    @staticmethod
    def _key_value(match: re.Match) -> str:
        value = match.group(5)
        if (
            len(value) < 3
            or value.lower().strip("[]") in HARMLESS_VALUES
            or value.startswith(("[REDACTED", "<", "{{", "$", "%"))
        ):
            return match.group(0)
        quote = match.group(4)
        return f"{match.group(1)}{match.group(2)}{match.group(1)}{match.group(3)}{quote}{REDACTED}"
