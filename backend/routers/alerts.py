"""Alerts — list, acknowledge, resolve."""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from middleware.clerk_auth import get_current_user
from database import get_database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
async def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]

    def _query(c):
        q = c.table("alerts").select("*").eq("org_id", org_id)
        if status_filter:
            q = q.eq("status", status_filter)
        if severity:
            q = q.eq("severity", severity)
        return q.order("created_at", desc=True).limit(limit).execute()

    resp = await db.execute(_query)
    return resp.data or []


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    await _set_status(alert_id, current_user["org"]["id"], "acknowledged", db)
    return {"message": "Alert acknowledged"}


@router.patch("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    await _set_status(alert_id, current_user["org"]["id"], "resolved", db)
    return {"message": "Alert resolved"}


async def _set_status(alert_id: str, org_id: str, new_status: str, db) -> None:
    check = await db.execute(
        lambda c: c.table("alerts")
        .select("id")
        .eq("id", alert_id)
        .eq("org_id", org_id)
        .execute()
    )
    if not check.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    await db.execute(
        lambda c: c.table("alerts")
        .update({
            "status": new_status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        .eq("id", alert_id)
        .execute()
    )
