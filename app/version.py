"""Version identity of the running application.

``APP_VERSION`` is set at image build time (``--build-arg APP_VERSION=…``, see the
Dockerfile and the release workflow). The build writes it to ``app/BUILD_VERSION``, which
wins over the ``VULNS_APP_VERSION`` environment variable: a container recreated from an
older one can inherit that variable with the old value, but never the file. Local runs
report ``dev``.

``SCHEMA_VERSION`` is the database schema this build expects; ``app.database`` stamps it
into the ``schema_migrations`` table as migrations are applied.
"""

import os
from pathlib import Path


def _build_version() -> str:
    try:
        return (Path(__file__).with_name("BUILD_VERSION")).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


APP_VERSION = _build_version() or os.getenv("VULNS_APP_VERSION", "").strip() or "dev"

SCHEMA_VERSION = 1
