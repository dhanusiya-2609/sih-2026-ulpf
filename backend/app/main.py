import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import settings, BASE_DIR
from .database import Base, engine, SessionLocal
from .models import ParserDefinition
from .auth import ensure_default_admin
from .parsers.registry import registry
from .ingestion.listeners import start_udp_listener, start_tcp_listener

from .api import (
    routes_auth, routes_sources, routes_ingest, routes_events,
    routes_dashboard, routes_export, routes_parsers, routes_training,
    routes_alerts, routes_misc,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ulpf.main")

_background_handles = []


def seed_parser_definitions(db):
    for p in registry.list_parsers():
        existing = db.query(ParserDefinition).filter(ParserDefinition.name == p.name).first()
        if not existing:
            db.add(ParserDefinition(
                name=p.name, version=p.version, format_family=p.format_family,
                description=f"Built-in {p.format_family.upper()} parser", is_builtin=True, is_active=True,
            ))
    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In production, schema is managed by Alembic migrations (see
    # `alembic upgrade head`, run automatically by docker-entrypoint.sh).
    # create_all() is kept as a zero-config convenience for local/dev use
    # and is a no-op for tables that already exist (e.g. after migrations
    # already ran), so it is safe to call unconditionally here.
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_default_admin(db)
        seed_parser_definitions(db)
    finally:
        db.close()

    if settings.ENABLE_UDP_LISTENER:
        try:
            handle = await start_udp_listener(settings.SYSLOG_UDP_HOST, settings.SYSLOG_UDP_PORT)
            _background_handles.append(handle)
        except Exception:
            logger.exception("Failed to start UDP syslog listener (port may be in use or unavailable)")
    if settings.ENABLE_TCP_LISTENER:
        try:
            server = await start_tcp_listener(settings.SYSLOG_TCP_HOST, settings.SYSLOG_TCP_PORT)
            _background_handles.append(server)
        except Exception:
            logger.exception("Failed to start TCP syslog listener (port may be in use or unavailable)")

    logger.info("ULPF backend ready.")
    yield

    for h in _background_handles:
        try:
            h.close()
        except Exception:
            pass
    logger.info("ULPF backend shutting down.")


app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # prototype only; restrict via reverse proxy in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (routes_auth.router, routes_sources.router, routes_ingest.router, routes_events.router,
          routes_dashboard.router, routes_export.router, routes_parsers.router, routes_training.router,
          routes_alerts.router, routes_misc.router):
    app.include_router(r)

STATIC_DIR = BASE_DIR / "app" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def root():
    return FileResponse(str(STATIC_DIR / "pages" / "login.html"))


@app.get("/{page_name}.html")
def serve_page(page_name: str):
    candidate = STATIC_DIR / "pages" / f"{page_name}.html"
    if candidate.exists():
        return FileResponse(str(candidate))
    return FileResponse(str(STATIC_DIR / "pages" / "login.html"))
