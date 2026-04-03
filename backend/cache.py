"""Shared async Redis cache — single pool, fail-open."""
import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis
from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis | None:
    global _pool
    if _pool is None:
        try:
            _pool = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                max_connections=20,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await _pool.ping()
            logger.info("Redis connected")
        except Exception as e:
            logger.warning("Redis unavailable (fail-open): %s", e)
            _pool = None
    return _pool


async def cache_get(key: str) -> Optional[Any]:
    try:
        r = await get_redis()
        if not r:
            return None
        val = await r.get(key)
        return json.loads(val) if val else None
    except Exception:
        return None


async def cache_set(key: str, value: Any, ttl: int = 60) -> bool:
    try:
        r = await get_redis()
        if not r:
            return False
        await r.set(key, json.dumps(value, default=str), ex=ttl)
        return True
    except Exception:
        return False


async def cache_delete(key: str) -> bool:
    try:
        r = await get_redis()
        if not r:
            return False
        await r.delete(key)
        return True
    except Exception:
        return False


async def close():
    global _pool
    if _pool:
        try:
            await _pool.aclose()
        except Exception:
            pass
        _pool = None
