"""Application factory."""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import agent
from .config import Settings
from .database import create_database, init_database
from .routes import ai_export, auth, dashboard, evidence, findings, knowledge, programs, search, tags
from .web import STATIC_DIR, render

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'"
)

# Starlette matches routes in order: routers with fixed /knowledge/... paths (export, tags)
# come before knowledge, whose /knowledge/{knowledge_id} would otherwise capture them.
ROUTERS = (
    auth.router,
    dashboard.router,
    search.router,
    programs.router,
    ai_export.router,
    tags.router,
    knowledge.router,
    evidence.router,
    findings.router,
    agent.router,
)


async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/static/"):
        # Asset URLs carry a content hash, so they can be cached forever.
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif "text/html" in response.headers.get("content-type", ""):
        # Never cache authenticated pages or their CSRF token.
        response.headers["Cache-Control"] = "no-store"
    return response


async def not_found(request: Request, _exc):
    return render(request, "404.html", status_code=404)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    for directory in (settings.data_dir, settings.evidence_dir, settings.markdown_dir):
        directory.mkdir(parents=True, exist_ok=True)
    engine, session_factory = create_database(settings.database_url)
    init_database(engine)

    app = FastAPI(title="VulnS", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.middleware("http")(security_headers)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="lax",
        https_only=settings.secure_cookies,
        max_age=60 * 60 * 24 * 30,
    )
    app.add_exception_handler(404, not_found)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    for router in ROUTERS:
        app.include_router(router)
    return app
