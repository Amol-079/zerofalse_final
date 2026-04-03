"""Webhook delivery — async, HMAC-signed, retried, logged."""
import asyncio
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = [1, 3, 10]
TIMEOUT = 10.0


def _sign(secret: str, payload: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def deliver_alert_webhooks(org_id: str, alert_id: str, scan_result, db) -> None:
    try:
        resp = await db.execute(
            lambda c: c.table("webhooks")
            .select("*")
            .eq("org_id", org_id)
            .eq("is_active", True)
            .execute()
        )
        webhooks = [
            wh for wh in (resp.data or [])
            if "alert.created" in (wh.get("events") or [])
        ]
        if not webhooks:
            return

        payload_bytes = json.dumps({
            "event": "alert.created",
            "alert_id": alert_id,
            "org_id": org_id,
            "threat_type": scan_result.threat_type,
            "decision": scan_result.decision,
            "risk_score": round(scan_result.risk_score, 4),
            "severity": scan_result.severity,
            "title": scan_result.title,
            "description": scan_result.description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            await asyncio.gather(*[
                _deliver(client, wh, payload_bytes, db)
                for wh in webhooks
            ], return_exceptions=True)

    except Exception as e:
        logger.error("deliver_alert_webhooks error: %s", e)


async def _deliver(client: httpx.AsyncClient, webhook: dict, payload: bytes, db) -> None:
    wid = webhook["id"]
    url = webhook["url"]
    secret = webhook.get("secret", "")
    sig = _sign(secret, payload) if secret else ""

    headers = {
        "Content-Type": "application/json",
        "X-Zerofalse-Signature": sig,
        "X-Zerofalse-Event": "alert.created",
        "User-Agent": "Zerofalse-Webhook/2.0",
    }

    success = False
    status_code: int | None = None
    last_error: str | None = None

    for attempt in range(MAX_RETRIES):
        try:
            r = await client.post(url, content=payload, headers=headers)
            status_code = r.status_code
            if 200 <= status_code < 300:
                success = True
                logger.info("Webhook %s delivered (attempt %d)", wid, attempt + 1)
                break
            last_error = f"HTTP {status_code}"
        except Exception as e:
            last_error = str(e)[:200]
            logger.warning("Webhook %s attempt %d error: %s", wid, attempt + 1, last_error)

        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(RETRY_DELAYS[attempt])

    try:
        delivery_id = str(uuid.uuid4())
        await db.execute(
            lambda c: c.table("webhook_deliveries").insert({
                "id": delivery_id,
                "webhook_id": wid,
                "success": success,
                "status_code": status_code,
                "error": last_error,
                "attempts": attempt + 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
        )
    except Exception as e:
        logger.warning("Failed to log webhook delivery: %s", e)
