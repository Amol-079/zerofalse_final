"""Clerk JWT authentication — fully async, PEM-based (no JWKS fetch)."""
import logging

import jwt
from fastapi import Header, HTTPException
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from cache import cache_get, cache_set, cache_delete
from config import get_settings
from database import AsyncDB

logger = logging.getLogger(__name__)
settings = get_settings()

AUTH_CACHE_TTL = 60
AUTH_CACHE_PREFIX = "auth:v2:"

# Load PEM key once at startup
_public_key = None

def _get_public_key():
    global _public_key
    if _public_key is None:
        pem = settings.CLERK_JWT_PUBLIC_KEY
        if not pem:
            raise RuntimeError("CLERK_JWT_PUBLIC_KEY not set")
        _public_key = load_pem_public_key(pem.encode())
    return _public_key


async def _verify_jwt(token: str) -> dict:
    try:
        key = _get_public_key()
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False}
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except Exception as e:
        logger.error("JWT verify error: %s", e)
        raise HTTPException(status_code=401, detail="Token verification failed")


async def get_current_user(
    authorization: str = Header(...)
) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    token = authorization.split(" ", 1)[1]
    claims = await _verify_jwt(token)
    clerk_user_id = claims.get("sub")
    if not clerk_user_id:
        raise HTTPException(
            status_code=401,
            detail="Token missing sub claim"
        )

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
        raise HTTPException(
            status_code=503,
            detail="Database temporarily unavailable"
        )

    if not resp.data:
        raise HTTPException(
            status_code=503,
            detail="User provisioning in progress. Please wait a moment.",
            headers={"Retry-After": "2"},
        )

    user = dict(resp.data)
    org = user.pop("organizations", None)
    if not org:
        raise HTTPException(
            status_code=503,
            detail="Organization not found for user"
        )

    result = {"user": user, "org": org}
    await cache_set(cache_key, result, ttl=AUTH_CACHE_TTL)
    return result


async def invalidate_user_cache(clerk_user_id: str) -> None:
    await cache_delete(f"{AUTH_CACHE_PREFIX}{clerk_user_id}")
