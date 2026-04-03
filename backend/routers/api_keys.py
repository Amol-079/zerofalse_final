"""API Keys — create, list, revoke."""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from middleware.clerk_auth import get_current_user
from database import get_database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/keys", tags=["api_keys"])


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


@router.get("/")
async def list_api_keys(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    resp = await db.execute(
        lambda c: c.table("api_keys")
        .select("id, name, key_prefix, is_active, total_calls, last_used_at, created_at")
        .eq("org_id", org_id)
        .order("created_at", desc=True)
        .execute()
    )
    return resp.data or []


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: CreateAPIKeyRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org = current_user["org"]
    raw_key = f"zf_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:16]
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        await db.execute(
            lambda c: c.table("api_keys").insert({
                "id": key_id,
                "org_id": org["id"],
                "name": data.name.strip(),
                "key_hash": key_hash,
                "key_prefix": key_prefix,
                "is_active": True,
                "total_calls": 0,
                "created_at": now,
                "updated_at": now,
            }).execute()
        )
    except Exception as e:
        logger.error("Create API key failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create API key. Please try again.")

    return {
        "id": key_id,
        "name": data.name.strip(),
        "key_prefix": key_prefix,
        "full_key": raw_key,
        "is_active": True,
        "created_at": now,
    }


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    check = await db.execute(
        lambda c: c.table("api_keys")
        .select("id")
        .eq("id", key_id)
        .eq("org_id", org_id)
        .execute()
    )
    if not check.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    try:
        await db.execute(
            lambda c: c.table("api_keys")
            .update({
                "is_active": False,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("id", key_id)
            .execute()
        )
    except Exception as e:
        logger.error("Revoke API key failed %s: %s", key_id, e)
        raise HTTPException(status_code=500, detail="Failed to revoke API key. Please try again.")

    return {"message": "API key revoked"}
