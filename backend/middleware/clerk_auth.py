"""Clerk JWT authentication — fully async, Redis-cached."""
import asyncio
import base64
import logging

import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException

from cache import cache_get, cache_set, cache_delete
from config import get_settings
from database import AsyncDB

logger = logging.getLogger(__name__)
settings = get_settings()

_jwks_client: PyJWKClient | None = None
_jwks_lock = asyncio.Lock()
AUTH_CACHE_TTL = 60
AUTH_CACHE_PREFIX = "auth:v2:"


def _derive_jwks_url() -> str:
    try:
        raw = settings.CLERK_SECRET_KEY
        parts = raw.split("_", 2)
        encoded = parts[2] if len(parts) == 3 else raw
        pad = 4 - len(encoded) % 4
        if pad != 4:
            encoded += "=" * pad
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        url = decoded.replace("\x00", "").strip()
        if url.startswith("https://"):
            return f"{url.rstrip('/')}/.well-known/jwks.json"
    except Exception as e:
        logger.warning("JWKS URL decode failed: %s", e)
    return "https://api.clerk.com/v1/jwks"


async def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        async with _jwks_lock:
            if _jwks_client is None:
                url = _derive_jwks_url()
                _jwks_client = PyJWKClient(
                    url,
                    lifespan=3600,
                    headers={"Authorization": f"Bearer {settings.CLERK_SECRET_KEY}"},
                )
    return _jwks_client


async def _verify_jwt(token: str) -> dict:
    try:
        c = await _get_jwks_client()
        loop = asyncio.get_event_loop()
        key = await loop.run_in_executor(None, c.get_signing_key_from_jwt, token)
        return jwt.decode(token, key.key, algorithms=["RS256"], options={"verify_exp": True})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except Exception as e:
        logger.error("JWT verify error: %s", e)
        raise HTTPException(status_code=401, detail="Token verification failed")


async def get_current_user(authorization: str = Header(...)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization.split(" ", 1)[1]
    claims = await _verify_jwt(token)
    clerk_user_id = claims.get("sub")
    if not clerk_user_id:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    cache_key = f"{AUTH_CACHE_PREFIX}{clerk_user_id}"
    cached = await cache_get(cache_key)
    if cached:
        return cached

    db = AsyncDB()
    try:
        resp = await db.execute(
            lambda c: c.table("users")
            .select("*, organizations(*)")
            .eq("clerk_user_id", clerk_user_id)
            .single()
            .execute()
        )
    except Exception as e:
        logger.error("DB user lookup error: %s", e)
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")

    if not resp.data:
        raise HTTPException(
            status_code=503,
            detail="User provisioning in progress. Please wait a moment.",
            headers={"Retry-After": "2"},
        )

    user = dict(resp.data)
    org = user.pop("organizations", None)
    if not org:
        raise HTTPException(status_code=503, detail="Organization not found for user")

    result = {"user": user, "org": org}
    await cache_set(cache_key, result, ttl=AUTH_CACHE_TTL)
    return result


async def invalidate_user_cache(clerk_user_id: str) -> None:
    await cache_delete(f"{AUTH_CACHE_PREFIX}{clerk_user_id}")
