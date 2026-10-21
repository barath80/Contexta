"""
Contexta Backend - Application entry point
"""

import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api import api_router
from app.bootstrap import bootstrap
from app.config import settings
from app.database import async_engine, init_db
from app.utils import ratelimit
from app.utils.net import client_ip
from app.utils.logging import setup_logging
from app.workers.scheduler import launch_background, setup_scheduler, shutdown_scheduler

setup_logging()
logger = structlog.get_logger()

VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_for_runtime()
    logger.info("Starting Contexta", version=VERSION, env=settings.app_env, database="sqlite" if settings.is_sqlite else "postgresql")
    if not settings.is_production:
        await init_db()  # dev/test convenience; production schema is managed by `alembic upgrade head`
    await bootstrap()
    setup_scheduler()
    if settings.scheduler_enabled and settings.sync_feeds_on_startup:
        launch_background("feed_sync")
        launch_background("risk_refresh")
    yield
    shutdown_scheduler()
    await async_engine.dispose()
    logger.info("Contexta stopped")


app = FastAPI(
    title="Contexta",
    description="Autonomous Context-Aware Threat Intelligence & Business Risk Platform",
    version=VERSION,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    expose_headers=["X-Request-ID", "Retry-After"],
)


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    start = time.perf_counter()
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    structlog.contextvars.bind_contextvars(request_id=request_id)

    # Global per-client rate limit (health checks and CORS preflight excluded)
    if request.method != "OPTIONS" and not request.url.path.startswith("/health"):
        ip = client_ip(request)
        allowed, retry = await ratelimit.hit(f"global:{ip}", settings.rate_limit_per_minute)
        if not allowed:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"},
                                headers={"Retry-After": str(retry), "X-Request-ID": request_id})
    try:
        response = await call_next(request)
    finally:
        structlog.contextvars.clear_contextvars()
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time-Ms"] = str(round((time.perf_counter() - start) * 1000, 1))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    errors = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": "Validation failed", "errors": errors})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", path=request.url.path, method=request.method, error=str(exc), exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe."""
    return {"status": "ok", "service": "contexta", "version": VERSION}


@app.get("/health/ready", tags=["Health"])
async def ready():
    """Readiness probe: database reachable."""
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Readiness check failed", error=str(exc))
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "unreachable"})
    return {"status": "ready", "database": "ok"}


@app.get("/", tags=["Root"])
async def root():
    return {"name": "Contexta", "version": VERSION, "api": settings.api_v1_prefix,
            "docs": None if settings.is_production else "/docs"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.app_env == "development")
