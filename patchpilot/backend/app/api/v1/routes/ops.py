"""Health check, readiness, and ops endpoints."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.core.config import settings

logger = structlog.get_logger(__name__)
ops_router = APIRouter(tags=["ops"])


@ops_router.get("/health", summary="Liveness probe")
async def health() -> dict[str, str]:
    """Basic liveness check – returns 200 if process is alive."""
    return {"status": "ok", "version": settings.APP_VERSION}


@ops_router.get("/ready", summary="Readiness probe – checks all dependencies")
async def ready() -> JSONResponse:
    """
    Readiness check: verifies DB, Redis, Qdrant, and ML service connectivity.
    Returns 503 if any critical dependency is unavailable.
    """
    checks: dict[str, Any] = {}
    all_ok = True

    # ─── PostgreSQL ────────────────────────────────────────────────────────
    try:
        from app.core.database import engine
        import sqlalchemy
        async with engine.connect() as conn:
            await conn.execute(sqlalchemy.text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {type(e).__name__}"
        all_ok = False

    # ─── Redis ────────────────────────────────────────────────────────────
    try:
        from app.core.redis_client import get_redis
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {type(e).__name__}"
        all_ok = False

    # ─── Qdrant ───────────────────────────────────────────────────────────
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{settings.QDRANT_URL}/healthz")
            checks["qdrant"] = "ok" if r.status_code == 200 else f"http_{r.status_code}"
    except Exception as e:
        checks["qdrant"] = f"error: {type(e).__name__}"
        # Qdrant down doesn't block scans, just RAG
        # Not marking all_ok = False here; treat as degraded

    # ─── ML Service ───────────────────────────────────────────────────────
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{settings.ML_SERVICE_URL}/health")
            checks["ml_service"] = "ok" if r.status_code == 200 else f"http_{r.status_code}"
    except Exception as e:
        checks["ml_service"] = f"error: {type(e).__name__}"
        # ML service down = degraded but not fatal for static analysis

    status_code = 200 if all_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if all_ok else "degraded",
            "checks": checks,
            "version": settings.APP_VERSION,
        },
    )
