"""Scan service — detection + async persistence. Security decision always returned."""
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from services.detection_engine import ScanResult, detection_engine

logger = logging.getLogger(__name__)


class ScanEvent:
    def __init__(self, id: str, created_at: datetime):
        self.id = id
        self.created_at = created_at


async def process_scan(
    org_id: str, api_key_id: str, tool_name: str, arguments: dict,
    agent_id: str, session_id: str = None, caller_agent_id: str = None, db=None,
) -> tuple[ScanResult, ScanEvent]:
    scan_result = detection_engine.scan(tool_name, arguments, agent_id, caller_agent_id)

    event_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    row = {
        "id": event_id, "org_id": org_id, "api_key_id": api_key_id,
        "agent_id": agent_id, "session_id": session_id,
        "caller_agent_id": caller_agent_id, "tool_name": tool_name,
        "arguments": arguments,
        "decision": scan_result.decision, "risk_score": scan_result.risk_score,
        "severity": scan_result.severity, "threat_type": scan_result.threat_type,
        "title": scan_result.title, "description": scan_result.description,
        "evidence": scan_result.evidence,
        "hint": getattr(scan_result, "hint", None),
        "safe_alternatives": getattr(scan_result, "safe_alternatives", []),
        "pattern_id": getattr(scan_result, "pattern_id", None),
        "latency_ms": scan_result.latency_ms, "created_at": now_iso,
    }

    if db is not None:
        try:
            await db.execute(lambda c: c.table("scan_events").insert(row).execute())
        except Exception as e:
            logger.error("scan_events persist failed (result still returned): %s", e)
        try:
            await db.execute(
                lambda c: c.rpc("increment_org_scan_count", {"org_id_input": org_id}).execute()
            )
        except Exception as e:
            logger.warning("increment_org_scan_count failed: %s", e)
        try:
            await db.execute(
                lambda c: c.rpc("increment_api_key_calls", {"key_id_input": api_key_id}).execute()
            )
        except Exception as e:
            logger.warning("increment_api_key_calls failed: %s", e)

    return scan_result, ScanEvent(id=event_id, created_at=datetime.fromisoformat(now_iso))


async def process_prompt_scan(
    org_id: str, api_key_id: str, text: str,
    agent_id: str, session_id: str = None, db=None,
) -> tuple[ScanResult, ScanEvent]:
    scan_result = detection_engine.scan_prompt(text)
    text_hash = hashlib.sha256(text.encode()).hexdigest()

    event_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    row = {
        "id": event_id, "org_id": org_id, "api_key_id": api_key_id,
        "agent_id": agent_id, "session_id": session_id,
        "tool_name": "prompt_scan", "arguments": {"text_hash": text_hash},
        "decision": scan_result.decision, "risk_score": scan_result.risk_score,
        "severity": scan_result.severity, "threat_type": scan_result.threat_type,
        "title": scan_result.title, "description": scan_result.description,
        "evidence": scan_result.evidence,
        "hint": getattr(scan_result, "hint", None),
        "safe_alternatives": getattr(scan_result, "safe_alternatives", []),
        "pattern_id": getattr(scan_result, "pattern_id", None),
        "latency_ms": scan_result.latency_ms, "created_at": now_iso,
    }

    if db is not None:
        try:
            await db.execute(lambda c: c.table("scan_events").insert(row).execute())
        except Exception as e:
            logger.error("prompt scan persist failed: %s", e)
        try:
            await db.execute(
                lambda c: c.rpc("increment_org_scan_count", {"org_id_input": org_id}).execute()
            )
        except Exception as e:
            logger.warning("increment_org_scan_count failed: %s", e)
        try:
            await db.execute(
                lambda c: c.rpc("increment_api_key_calls", {"key_id_input": api_key_id}).execute()
            )
        except Exception as e:
            logger.warning("increment_api_key_calls failed: %s", e)

    return scan_result, ScanEvent(id=event_id, created_at=datetime.fromisoformat(now_iso))
