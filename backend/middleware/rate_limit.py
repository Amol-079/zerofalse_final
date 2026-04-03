"""Rate limiting — sliding window via shared Redis pool. Fail-open."""
import time
import logging
from fastapi import HTTPException, Request, status
from cache import get_redis

logger = logging.getLogger(__name__)

_TRUSTED_PROXY = ("127.", "::1", "10.", "172.16.", "172.17.", "172.18.",
                   "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                   "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                   "172.29.", "172.30.", "172.31.", "192.168.")


def _client_ip(request: Request) -> str:
    direct = request.client.host if request.client else "unknown"
    if any(direct.startswith(p) for p in _TRUSTED_PROXY):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return direct


async def _sliding_window(key: str, limit: int, window: int = 60) -> None:
    try:
        r = await get_redis()
        if not r:
            return
        now = time.time()
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window + 1)
        _, count, _, _ = await pipe.execute()
        if count >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(window)},
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Rate limiter error (fail-open): %s", e)


async def rate_limit_auth(request: Request) -> None:
    ip = _client_ip(request)
    await _sliding_window(f"rl:auth:{ip}", limit=100, window=60)


async def rate_limit_scan(request: Request) -> None:
    api_key = request.headers.get("X-API-Key", "")
    identifier = api_key[:16] if api_key else _client_ip(request)
    await _sliding_window(f"rl:scan:{identifier}", limit=1000, window=60)


async def rate_limit_dashboard(request: Request) -> None:
    ip = _client_ip(request)
    await _sliding_window(f"rl:dash:{ip}", limit=60, window=60)
