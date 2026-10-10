"""Scan service: enqueues scan jobs via Arq and provides scan orchestration helpers."""

from __future__ import annotations

import structlog
from redis.asyncio import Redis

from app.core.config import settings
from app.core.redis_client import get_redis

logger = structlog.get_logger(__name__)

ARQ_QUEUE_KEY = "arq:jobs:default"


async def enqueue_scan(scan_id: str) -> None:
    """
    Enqueue a scan job via Arq.
    
    Uses Redis list push; Arq workers poll this queue.
    """
    import json
    import time
    redis = await get_redis()

    job_payload = {
        "function": "process_scan",
        "args": [scan_id],
        "kwargs": {},
        "job_id": scan_id,
        "enqueue_time": time.time(),
    }

    # Push to Arq's queue (serialize as expected by arq)
    await redis.rpush(ARQ_QUEUE_KEY, json.dumps(job_payload))
    
    # Publish initial progress event
    await publish_scan_progress(
        scan_id=scan_id,
        step="queued",
        message="Scan queued for processing",
        progress=0.0,
    )
    logger.info("scan_enqueued", scan_id=scan_id)


async def publish_scan_progress(
    scan_id: str,
    step: str,
    message: str,
    progress: float,
    data: dict | None = None,
) -> None:
    """Publish a scan progress event to Redis pub/sub for SSE consumers."""
    import json
    redis = await get_redis()
    channel = f"scan:progress:{scan_id}"
    payload = {
        "scan_id": scan_id,
        "step": step,
        "message": message,
        "progress": progress,
        "data": data or {},
    }
    await redis.publish(channel, json.dumps(payload))
