"""PatchPilot FastAPI application entry point."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from app.core.config import settings
from app.core.database import engine, init_db
from app.core.logging import configure_logging
from app.core.redis_client import get_redis_pool, close_redis_pool
from app.api.v1.router import api_router

# Configure structured logging early
configure_logging(settings.LOG_LEVEL)
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup and shutdown events."""
    logger.info("patchpilot_starting", version=settings.APP_VERSION, env=settings.APP_ENV)
    
    # Initialize DB connection pool
    await init_db()
    logger.info("database_ready")
    
    # Initialize Redis connection pool
    await get_redis_pool()
    logger.info("redis_ready")
    
    yield
    
    # Graceful shutdown
    await close_redis_pool()
    await engine.dispose()
    logger.info("patchpilot_shutdown")


def create_app() -> FastAPI:
    """Factory function to create the FastAPI application."""
    app = FastAPI(
        title="PatchPilot API",
        description=(
            "Evidence-grounded vulnerability triage & remediation copilot. "
            "DEFENSIVE ONLY – never generates exploit code."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ─── Middleware ────────────────────────────────────────────────────────────
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS_LIST,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining"],
    )

    # ─── Request ID & Timing Middleware ───────────────────────────────────────
    @app.middleware("http")
    async def add_request_id_and_timing(request: Request, call_next) -> Response:  # type: ignore
        import uuid
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()
        
        # Bind to structlog context
        with structlog.contextvars.bound_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        ):
            response = await call_next(request)
            duration_ms = (time.monotonic() - start_time) * 1000
            
            response.headers["X-Request-ID"] = request_id
            logger.info(
                "http_request",
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
        return response

    # ─── Security Headers Middleware ──────────────────────────────────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:  # type: ignore
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # CSP: no inline scripts allowed (enforced via nonce in frontend)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "  # Required for Vite HMR in dev
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:;"
        )
        return response

    # ─── Global Error Handler ─────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_exception", exc_type=type(exc).__name__, exc_msg=str(exc))
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred", "details": None}},
        )

    # ─── Routes ───────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    # ─── Health / Metrics ─────────────────────────────────────────────────────
    from app.api.v1.routes.ops import ops_router
    app.include_router(ops_router)

    # Prometheus metrics endpoint
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app


app = create_app()
