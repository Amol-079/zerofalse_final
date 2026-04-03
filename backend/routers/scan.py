"""Scan router — tool-call, prompt, batch, history."""
import asyncio
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status

from database import get_database
from middleware.api_key_auth import get_api_key_org
from middleware.clerk_auth import get_current_user
from middleware.rate_limit import rate_limit_scan
from schemas.scan import (
    BatchScanRequest, PromptScanRequest,
    ScanResponse, ToolCallScanRequest,
)
from services.alert_service import create_alert_if_needed
from services.scan_service import process_prompt_scan, process_scan
from services.webhook_service import deliver_alert_webhooks

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/scan",
    tags=["scan"],
    dependencies=[Depends(rate_limit_scan)],
)


async def _check_quota(org_id: str, needed: int, db) -> None:
    """Live quota check — reads current count directly, not stale cache."""
    try:
        resp = await db.execute(
            lambda c: c.table("organizations")
            .select("scan_count_month, scan_limit_month")
            .eq("id", org_id)
            .single()
            .execute()
        )
        if resp.data:
            used = resp.data.get("scan_count_month", 0)
            limit = resp.data.get("scan_limit_month", 1000)
            if used + needed > limit:
                remaining = max(0, limit - used)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Monthly quota exceeded. {remaining} scans remaining of {limit}.",
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Quota check failed (allowing): %s", e)


def _build_response(scan_result, scan_event) -> ScanResponse:
    return ScanResponse(
        scan_id=scan_event.id,
        decision=scan_result.decision,
        risk_score=scan_result.risk_score,
        severity=scan_result.severity,
        threat_type=scan_result.threat_type,
        title=scan_result.title,
        description=scan_result.description,
        evidence=scan_result.evidence,
        latency_ms=scan_result.latency_ms,
        timestamp=scan_event.created_at,
        hint=getattr(scan_result, "hint", None),
        safe_alternatives=getattr(scan_result, "safe_alternatives", []),
        retry_allowed=getattr(scan_result, "retry_allowed", True),
        action_taken=getattr(scan_result, "action_taken", "logged"),
        pattern_id=getattr(scan_result, "pattern_id", None),
    )


@router.post("/tool-call", response_model=ScanResponse)
async def scan_tool_call(
    data: ToolCallScanRequest,
    api_key_org: tuple = Depends(get_api_key_org),
    db=Depends(get_database),
):
    api_key, org = api_key_org
    await _check_quota(org["id"], 1, db)

    scan_result, scan_event = await process_scan(
        org_id=org["id"], api_key_id=api_key["id"],
        tool_name=data.tool_name, arguments=data.arguments,
        agent_id=data.agent_id, session_id=data.session_id,
        caller_agent_id=data.caller_agent_id, db=db,
    )
    alert_id = await create_alert_if_needed(org["id"], scan_event.id, scan_result, data.agent_id, db)
    if alert_id:
        asyncio.create_task(deliver_alert_webhooks(org["id"], alert_id, scan_result, db))

    return _build_response(scan_result, scan_event)


@router.post("/prompt", response_model=ScanResponse)
async def scan_prompt_endpoint(
    data: PromptScanRequest,
    api_key_org: tuple = Depends(get_api_key_org),
    db=Depends(get_database),
):
    api_key, org = api_key_org
    await _check_quota(org["id"], 1, db)

    scan_result, scan_event = await process_prompt_scan(
        org_id=org["id"], api_key_id=api_key["id"],
        text=data.text, agent_id=data.agent_id,
        session_id=data.session_id, db=db,
    )
    alert_id = await create_alert_if_needed(org["id"], scan_event.id, scan_result, data.agent_id, db)
    if alert_id:
        asyncio.create_task(deliver_alert_webhooks(org["id"], alert_id, scan_result, db))

    return _build_response(scan_result, scan_event)


@router.post("/batch", response_model=List[ScanResponse])
async def batch_scan(
    data: BatchScanRequest,
    api_key_org: tuple = Depends(get_api_key_org),
    db=Depends(get_database),
):
    api_key, org = api_key_org
    await _check_quota(org["id"], len(data.scans), db)

    pairs = await asyncio.gather(*[
        process_scan(
            org_id=org["id"], api_key_id=api_key["id"],
            tool_name=req.tool_name, arguments=req.arguments,
            agent_id=req.agent_id, session_id=req.session_id,
            caller_agent_id=req.caller_agent_id, db=db,
        )
        for req in data.scans
    ])

    results = []
    for (scan_result, scan_event), req in zip(pairs, data.scans):
        alert_id = await create_alert_if_needed(org["id"], scan_event.id, scan_result, req.agent_id, db)
        if alert_id:
            asyncio.create_task(deliver_alert_webhooks(org["id"], alert_id, scan_result, db))
        results.append(_build_response(scan_result, scan_event))
    return results


@router.get("/history")
async def get_scan_history(
    limit: int = Query(default=50, ge=1, le=200),
    page: int = Query(default=1, ge=1),
    decision: str = Query(default=None),
    agent_id: str = Query(default=None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    offset = (page - 1) * limit

    def _query(c):
        q = c.table("scan_events").select("*", count="exact").eq("org_id", org_id)
        if decision and decision != "all":
            q = q.eq("decision", decision)
        if agent_id:
            q = q.eq("agent_id", agent_id)
        return q.order("created_at", desc=True).range(offset, offset + limit - 1).execute()

    resp = await db.execute(_query)
    total = resp.count or 0
    return {
        "scans": resp.data or [],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
    }
