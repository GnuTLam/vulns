import re
import unicodedata
from collections.abc import Iterable

SEVERITIES = ("informational", "low", "medium", "high", "critical")

MAX_TAGS = 12
TAG_MAX_LENGTH = 40

# Payout currencies. Rewards are totalled per currency, never across currencies.
CURRENCIES = ("USD", "EUR", "GBP", "VND", "SGD", "JPY", "INR", "AUD", "CAD", "CHF", "BTC")
DEFAULT_CURRENCY = "USD"
STATUSES = (
    "draft",
    "not_submitted",
    "ready_to_submit",
    "submitted",
    "triaged",
    "accepted",
    "rejected",
    "duplicate",
    "informative",
    "out_of_scope",
    "resolved",
    "paid",
    "archived",
)
BUG_TYPES = (
    "Access Control",
    "Authentication",
    "Business Logic",
    "CSRF",
    "Cryptography",
    "File Upload",
    "Information Disclosure",
    "Injection",
    "Mobile",
    "OAuth / SSO",
    "Race Condition",
    "Request Smuggling",
    "SSRF",
    "XSS",
    "Other",
)


def normalize_tag(value: str) -> str:
    """Canonical tag form: ASCII, lowercase, words joined by hyphens (``Account Takeover`` -> ``account-takeover``)."""
    folded = unicodedata.normalize("NFKD", value.replace("đ", "d").replace("Đ", "D"))
    folded = "".join(char for char in folded if not unicodedata.combining(char)).casefold()
    folded = re.sub(r"[\s_/]+", "-", folded.strip())
    folded = re.sub(r"[^a-z0-9.+#-]", "", folded)
    folded = re.sub(r"-{2,}", "-", folded).strip("-.")
    return folded[:TAG_MAX_LENGTH].strip("-.")


def parse_tags(raw: str | Iterable[str] | None) -> list[str]:
    """Normalise a comma-separated string or a list of tags, dropping blanks and duplicates."""
    if raw is None:
        return []
    parts = re.split(r"[,\n]", raw) if isinstance(raw, str) else [str(item) for item in raw]
    tags = [normalize_tag(part) for part in parts]
    return list(dict.fromkeys(tag for tag in tags if tag))[:MAX_TAGS]
