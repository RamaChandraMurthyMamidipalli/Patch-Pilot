"""Redis connection pool management."""

from __future__ import annotations

from typing import Optional

import redis.asyncio as aioredis
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

_pool: Optional[aioredis.ConnectionPool] = None
_client: Optional[aioredis.Redis] = None


async def get_redis_pool() -> Optional[aioredis.ConnectionPool]:
    """Initialize and return the Redis connection pool."""
    global _pool, _client
    if _pool is None and _client is None:
        try:
            _pool = aioredis.ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=50,
                decode_responses=True,
            )
            _client = aioredis.Redis(connection_pool=_pool)
            await _client.ping()
            logger.info("redis_connection_pool_created")
        except Exception as exc:
            logger.warning("redis_unavailable_running_in_standalone_mode", error=str(exc))
            from fakeredis.aioredis import FakeRedis
            _client = FakeRedis(decode_responses=True)
            _pool = None
    return _pool


async def get_redis() -> aioredis.Redis:
    """FastAPI dependency: return Redis client."""
    global _client
    if _client is None:
        await get_redis_pool()
    return _client


async def close_redis_pool() -> None:
    """Gracefully close the Redis connection pool."""
    global _pool, _client
    if _client is not None:
        await _client.aclose()
        _client = None
    if _pool is not None:
        await _pool.aclose()
        _pool = None
    logger.info("redis_connection_pool_closed")
