"""Webhooks — create, list, delete. Secret stored raw for HMAC signing."""
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl

from middleware.clerk_auth import get_current_user
from database import get_database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class CreateWebhookRequest(BaseModel):
    url: HttpUrl
    events: List[str]


@router.get("/")
async def list_webhooks(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    resp = await db.execute(
        lambda c: c.table("webhooks")
        .select("id, url, events, is_active, created_at")
        .eq("org_id", org_id)
        .order("created_at", desc=True)
        .execute()
    )
    return resp.data or []


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    data: CreateWebhookRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    # Store raw secret — needed for HMAC signing. Protected by service_role key.
    raw_secret = secrets.token_urlsafe(32)
    webhook_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        lambda c: c.table("webhooks").insert({
            "id": webhook_id,
            "org_id": org_id,
            "url": str(data.url),
            "events": data.events,
            "secret": raw_secret,
            "is_active": True,
            "created_at": now,
        }).execute()
    )

    return {
        "id": webhook_id,
        "url": str(data.url),
        "events": data.events,
        "is_active": True,
        "created_at": now,
        "secret": raw_secret,
    }


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    check = await db.execute(
        lambda c: c.table("webhooks")
        .select("id")
        .eq("id", webhook_id)
        .eq("org_id", org_id)
        .execute()
    )
    if not check.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    await db.execute(
        lambda c: c.table("webhooks").delete().eq("id", webhook_id).execute()
    )
    return {"message": "Webhook deleted"}
