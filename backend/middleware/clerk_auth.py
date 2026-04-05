"""Clerk JWT authentication — clean, stable version"""

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

# Load PEM key once
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
    # 1. Check header
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    # 2. Decode token
    token = authorization.split(" ", 1)[1]
    claims = await _verify_jwt(token)

    clerk_user_id = claims.get("sub")

    if not clerk_user_id:
        raise HTTPException(
            status_code=401,
            detail="Token missing sub claim"
        )

    # 3. Cache check
    cache_key = f"{AUTH_CACHE_PREFIX}{clerk_user_id}"
    cached = await cache_get(cache_key)
    if cached:
        return cached

    db = AsyncDB()

    # 4. Try to get user
    try:
        resp = await db.execute(
            lambda c: c.table("users")
            .select("*")
            .eq("clerk_user_id", clerk_user_id)
            .maybe_single()
            .execute()
        )
    except Exception as e:
        logger.error("DB error: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        )

    # 5. If user NOT found → create
    if not resp.data:
        try:
            # create org
            org_resp = await db.execute(
                lambda c: c.table("organizations")
                .insert({"name": "Default Org"})
                .execute()
            )
            org = org_resp.data[0]

            # create user
            user_resp = await db.execute(
                lambda c: c.table("users")
                .insert({
                    "clerk_user_id": clerk_user_id,
                    "email": claims.get("email"),
                    "full_name": claims.get("name"),
                    "org_id": org["id"]
                })
                .execute()
            )

            user = user_resp.data[0]

        except Exception as e:
            logger.error("User creation failed: %s", e)
            raise HTTPException(
                status_code=500,
                detail="User creation failed"
            )
    else:
        user = resp.data

    # 6. Cache + return
    result = {"user": user}
    await cache_set(cache_key, result, ttl=AUTH_CACHE_TTL)

    return result


async def invalidate_user_cache(clerk_user_id: str) -> None:
    await cache_delete(f"{AUTH_CACHE_PREFIX}{clerk_user_id}")
