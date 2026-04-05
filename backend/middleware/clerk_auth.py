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
    uid = clerk_user_id

    # Get user - removed maybe_single()
    try:
        resp = await db.execute(
            lambda c: c.table("users")
            .select("*")
            .eq("clerk_user_id", uid)
            .execute()
        )
        user_data = resp.data[0] if resp and resp.data else None
    except Exception as e:
        logger.error("DB error fetching user: %s", e)
        raise HTTPException(status_code=503, detail="Database unavailable")

    if user_data is None:
        try:
            slug = f"org-{uid[-8:]}"
            org_resp = await db.execute(
                lambda c: c.table("organizations")
                .insert({"name": "Default Org", "slug": slug})
                .execute()
            )
            if org_resp is None or not org_resp.data:
                raise Exception("Org insert returned no data")
            org = org_resp.data[0]
            org_id = org["id"]

            user_resp = await db.execute(
                lambda c: c.table("users")
                .insert({
                    "clerk_user_id": uid,
                    "email": claims.get("email", ""),
                    "full_name": claims.get("name", ""),
                    "org_id": org_id,
                    "role": "admin"
                })
                .execute()
            )
            if user_resp is None or not user_resp.data:
                raise Exception("User insert returned no data")
            user = user_resp.data[0]

        except Exception as e:
            logger.error("User creation failed: %s", e)
            raise HTTPException(
                status_code=500,
                detail="User creation failed"
            )
    else:
        user = user_data

    # Get org - removed single()
    org_id = user["org_id"]
    try:
        org_resp = await db.execute(
            lambda c: c.table("organizations")
            .select("*")
            .eq("id", org_id)
            .execute()
        )
        org = org_resp.data[0] if org_resp and org_resp.data else None
        if not org:
            raise Exception("Org not found")
    except Exception as e:
        logger.error("DB error fetching org: %s", e)
        raise HTTPException(status_code=503, detail="Database unavailable")

    result = {"user": user, "org": org}
    await cache_set(cache_key, result, ttl=AUTH_CACHE_TTL)
    return result


async def invalidate_user_cache(clerk_user_id: str) -> None:
    await cache_delete(f"{AUTH_CACHE_PREFIX}{clerk_user_id}")
