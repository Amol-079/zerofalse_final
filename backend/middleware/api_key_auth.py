"""API Key authentication — async."""
import hashlib
import logging
from datetime import datetime, timezone

from fastapi import Header, HTTPException, status, Depends
from database import get_database

logger = logging.getLogger(__name__)


async def get_api_key_org(
    x_api_key: str = Header(...),
    db=Depends(get_database),
) -> tuple[dict, dict]:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key missing")

    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    resp = await db.execute(
        lambda c: c.table("api_keys")
        .select("*, organizations(*)")
        .eq("key_hash", key_hash)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )

    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
        )

    api_key = dict(resp.data[0])
    org = api_key.pop("organizations", None)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Organization not found for API key",
        )

    try:
        await db.execute(
            lambda c: c.table("api_keys")
            .update({"last_used_at": datetime.now(timezone.utc).isoformat()})
            .eq("id", api_key["id"])
            .execute()
        )
    except Exception as e:
        logger.warning("Failed to update last_used_at: %s", e)

    return api_key, org
