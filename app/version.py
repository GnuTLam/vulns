"""Version identity of the running application.

``APP_VERSION`` is injected at image build time (``--build-arg APP_VERSION=…``, see the
Dockerfile and the release workflow) and read from the environment here so a release
image always knows its own tag. Local runs report ``dev``.

``SCHEMA_VERSION`` is the database schema this build expects; ``app.database`` stamps it
into the ``schema_migrations`` table as migrations are applied.
"""

import os

APP_VERSION = os.getenv("VULNS_APP_VERSION", "dev")

SCHEMA_VERSION = 1
