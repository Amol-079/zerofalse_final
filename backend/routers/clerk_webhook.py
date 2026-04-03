"""Clerk webhook — atomic user+org creation, idempotent, rollback-safe."""
import logging
import secrets

from fastapi import APIRouter, Request, HTTPException, Header
from svix.webhooks import Webhook, WebhookVerificationError

from config import get_settings
from database import get_supabase
from middleware.clerk_auth import invalidate_user_cache

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/auth", tags=["clerk-webhook"])


@router.post("/webhook/clerk")
async def clerk_webhook(
    request: Request,
    svix_id: str = Header(None, alias="svix-id"),
    svix_timestamp: str = Header(None, alias="svix-timestamp"),
    svix_signature: str = Header(None, alias="svix-signature"),
):
    body = await request.body()
    if not all([svix_id, svix_timestamp, svix_signature]):
        raise HTTPException(status_code=400, detail="Missing svix headers")
    try:
        wh = Webhook(settings.CLERK_WEBHOOK_SECRET)
        event = wh.verify(body, {
            "svix-id": svix_id,
            "svix-timestamp": svix_timestamp,
            "svix-signature": svix_signature,
        })
    except WebhookVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event_type = event.get("type")
    data = event.get("data", {})
    logger.info("Clerk webhook: %s user=%s", event_type, data.get("id"))

    if event_type == "user.created":
        await _handle_created(data)
    elif event_type == "user.updated":
        await _handle_updated(data)
    elif event_type == "user.deleted":
        await _handle_deleted(data)

    return {"status": "ok"}


async def _handle_created(data: dict) -> None:
    db = get_supabase()
    clerk_user_id = data["id"]

    existing = db.table("users").select("id").eq("clerk_user_id", clerk_user_id).execute()
    if existing.data:
        logger.info("user.created: %s already exists, skipping", clerk_user_id)
        return

    emails = data.get("email_addresses", [])
    email = emails[0].get("email_address", "") if emails else ""
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    full_name = f"{first} {last}".strip() or email.split("@")[0]

    prefix = email.split("@")[0].lower().replace(".", "-").replace("+", "-")[:30]
    slug = f"{prefix}-{secrets.token_hex(3)}"

    org_id: str | None = None
    try:
        org_resp = db.table("organizations").insert({
            "name": f"{full_name}'s Organization",
            "slug": slug,
        }).execute()
        if not org_resp.data:
            logger.error("Failed to create org for %s", clerk_user_id)
            return
        org_id = org_resp.data[0]["id"]

        db.table("users").insert({
            "clerk_user_id": clerk_user_id,
            "email": email,
            "full_name": full_name,
            "org_id": org_id,
            "role": "owner",
        }).execute()
        logger.info("Provisioned user %s org %s", clerk_user_id, org_id)

    except Exception as e:
        logger.error("Provisioning error %s: %s", clerk_user_id, e)
        if org_id:
            try:
                db.table("organizations").delete().eq("id", org_id).execute()
                logger.info("Rolled back orphan org %s", org_id)
            except Exception as rb_err:
                logger.error("Rollback failed for org %s: %s", org_id, rb_err)


async def _handle_updated(data: dict) -> None:
    clerk_user_id = data.get("id")
    if clerk_user_id:
        await invalidate_user_cache(clerk_user_id)
        logger.info("Cache invalidated: %s", clerk_user_id)


async def _handle_deleted(data: dict) -> None:
    db = get_supabase()
    clerk_user_id = data.get("id")
    if not clerk_user_id:
        return
    try:
        user_resp = db.table("users").select("org_id").eq("clerk_user_id", clerk_user_id).execute()
        org_id = user_resp.data[0]["org_id"] if user_resp.data else None
        await invalidate_user_cache(clerk_user_id)
        db.table("users").delete().eq("clerk_user_id", clerk_user_id).execute()
        if org_id:
            remaining = db.table("users").select("id").eq("org_id", org_id).execute()
            if not remaining.data:
                db.table("organizations").delete().eq("id", org_id).execute()
                logger.info("Deleted orphan org %s", org_id)
        logger.info("Deleted user %s", clerk_user_id)
    except Exception as e:
        logger.error("Delete user error %s: %s", clerk_user_id, e)
