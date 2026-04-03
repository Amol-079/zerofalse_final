"""Alert service — dedup scoped to threat_type + agent_id."""
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from services.detection_engine import ScanResult

logger = logging.getLogger(__name__)


async def create_alert_if_needed(
    org_id: str, scan_event_id: str, scan_result: ScanResult,
    agent_id: str, db,
) -> Optional[str]:
    if scan_result.decision != "block" and scan_result.severity not in ("critical", "high"):
        return None

    five_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    try:
        def _dedup_query(c):
            q = (
                c.table("alerts").select("id")
                .eq("org_id", org_id)
                .eq("status", "open")
                .gte("created_at", five_min_ago)
            )
            if scan_result.threat_type:
                q = q.eq("threat_type", scan_result.threat_type)
            if agent_id:
                q = q.eq("agent_id", agent_id)
            return q.limit(1).execute()

        existing = await db.execute(_dedup_query)
        if existing.data:
            return None
    except Exception as e:
        logger.warning("Alert dedup failed (non-fatal): %s", e)

    alert_id = str(uuid.uuid4())
    severity = scan_result.severity if scan_result.severity in ("critical", "high", "medium", "low") else "medium"
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        await db.execute(
            lambda c: c.table("alerts").insert({
                "id": alert_id,
                "org_id": org_id,
                "scan_event_id": scan_event_id,
                "agent_id": agent_id,
                "threat_type": scan_result.threat_type,
                "severity": severity,
                "title": scan_result.title,
                "description": scan_result.description,
                "status": "open",
                "created_at": now_iso,
                "updated_at": now_iso,
            }).execute()
        )
        logger.info("Alert created: org=%s threat=%s agent=%s", org_id, scan_result.threat_type, agent_id)
        return alert_id
    except Exception as e:
        logger.error("Failed to create alert: %s", e)
        return None
