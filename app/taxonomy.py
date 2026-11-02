import re
import unicodedata
from collections.abc import Iterable

SEVERITIES = ("informational", "low", "medium", "high", "critical")

MAX_TAGS = 12
TAG_MAX_LENGTH = 40

# Payout currencies. Rewards are totalled per currency, never across currencies.
CURRENCIES = ("VND", "EUR", "USD")
CURRENCY_SYMBOLS = {"VND": "₫", "EUR": "€", "USD": "$"}
# Offered by earlier versions. Rows that already use one keep it, but it cannot be chosen anew.
LEGACY_CURRENCIES = ("GBP", "SGD", "JPY", "INR", "AUD", "CAD", "CHF", "BTC")
DEFAULT_CURRENCY = "USD"
# Where a submission stands; what the program decided is kept separately as its outcome.
STATUSES = ("submitted", "processing", "done")
OUTCOMES = ("", "accepted", "duplicate", "informative", "rejected", "out_of_scope")
# Statuses that no longer need attention; `is:open` is the complement.
CLOSED_STATUSES = ("done",)
# Earlier lifecycle values -> (status, outcome, paid), applied once at startup.
LEGACY_STATUSES = {
    "draft": ("submitted", "", False),
    "not_submitted": ("submitted", "", False),
    "ready_to_submit": ("submitted", "", False),
    "triaged": ("processing", "", False),
    "accepted": ("processing", "accepted", False),
    "resolved": ("done", "accepted", False),
    "paid": ("done", "accepted", True),
    "rejected": ("done", "rejected", False),
    "duplicate": ("done", "duplicate", False),
    "informative": ("done", "informative", False),
    "out_of_scope": ("done", "out_of_scope", False),
    "archived": ("done", "", False),
}
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
