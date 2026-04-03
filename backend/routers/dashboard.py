"""Dashboard — parallel async queries, Redis-cached."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from cache import cache_get, cache_set
from database import get_database
from middleware.clerk_auth import get_current_user
from middleware.rate_limit import rate_limit_dashboard

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(rate_limit_dashboard)],
)


@router.get("/stats")
async def get_stats(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    cache_key = f"dash:stats:{org_id}"
    cached = await cache_get(cache_key)
    if cached:
        return cached

    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week = (now - timedelta(days=7)).isoformat()
    month = (now - timedelta(days=30)).isoformat()
    trend_start = (now - timedelta(days=14)).isoformat()

    (
        r_today, r_week, r_month,
        r_block_today, r_warn_today,
        r_open, r_crit,
        r_agents, r_threats, r_trend,
    ) = await asyncio.gather(
        db.execute(lambda c: c.table("scan_events").select("id", count="exact")
                   .eq("org_id", org_id).gte("created_at", today).execute()),
        db.execute(lambda c: c.table("scan_events").select("id", count="exact")
                   .eq("org_id", org_id).gte("created_at", week).execute()),
        db.execute(lambda c: c.table("scan_events").select("id", count="exact")
                   .eq("org_id", org_id).gte("created_at", month).execute()),
        db.execute(lambda c: c.table("scan_events").select("id", count="exact")
                   .eq("org_id", org_id).eq("decision", "block").gte("created_at", today).execute()),
        db.execute(lambda c: c.table("scan_events").select("id", count="exact")
                   .eq("org_id", org_id).eq("decision", "warn").gte("created_at", today).execute()),
        db.execute(lambda c: c.table("alerts").select("id", count="exact")
                   .eq("org_id", org_id).eq("status", "open").execute()),
        db.execute(lambda c: c.table("alerts").select("id", count="exact")
                   .eq("org_id", org_id).eq("status", "open").eq("severity", "critical").execute()),
        db.execute(lambda c: c.table("scan_events").select("agent_id")
                   .eq("org_id", org_id).gte("created_at", week).execute()),
        db.execute(lambda c: c.table("scan_events").select("threat_type")
                   .eq("org_id", org_id).gte("created_at", month)
                   .not_.is_("threat_type", "null").execute()),
        db.execute(lambda c: c.table("scan_events").select("decision, created_at")
                   .eq("org_id", org_id).gte("created_at", trend_start).limit(50000).execute()),
    )

    active_agents = len({r["agent_id"] for r in (r_agents.data or []) if r.get("agent_id")})

    threat_counts: dict[str, int] = {}
    for r in (r_threats.data or []):
        t = r.get("threat_type")
        if t:
            threat_counts[t] = threat_counts.get(t, 0) + 1
    top_threat = max(threat_counts, key=threat_counts.get) if threat_counts else None

    buckets: dict[str, dict] = {}
    for i in range(13, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[day] = {"date": day, "total": 0, "blocked": 0, "warned": 0}
    for r in (r_trend.data or []):
        day = (r.get("created_at") or "")[:10]
        if day in buckets:
            buckets[day]["total"] += 1
            d = r.get("decision", "")
            if d == "block":
                buckets[day]["blocked"] += 1
            elif d == "warn":
                buckets[day]["warned"] += 1

    org = current_user["org"]
    result = {
        "total_scans_today":  r_today.count or 0,
        "total_scans_week":   r_week.count or 0,
        "total_scans_month":  r_month.count or 0,
        "blocked_today":      r_block_today.count or 0,
        "warned_today":       r_warn_today.count or 0,
        "open_alerts":        r_open.count or 0,
        "critical_alerts":    r_crit.count or 0,
        "active_agents":      active_agents,
        "top_threat_type":    top_threat,
        "scan_limit_month":   org.get("scan_limit_month", 1000),
        "scan_used_month":    org.get("scan_count_month", 0),
        "daily_trend":        list(buckets.values()),
    }
    await cache_set(cache_key, result, ttl=60)
    return result


@router.get("/threat-breakdown")
async def get_threat_breakdown(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    org_id = current_user["org"]["id"]
    cache_key = f"dash:breakdown:{org_id}"
    cached = await cache_get(cache_key)
    if cached:
        return cached

    month_start = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    resp = await db.execute(
        lambda c: c.table("scan_events")
        .select("threat_type, severity, decision, agent_id")
        .eq("org_id", org_id)
        .gte("created_at", month_start)
        .limit(10000)
        .execute()
    )
    rows = resp.data or []

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_decision: dict[str, int] = {}
    agent_map: dict[str, dict] = {}

    for r in rows:
        if t := r.get("threat_type"):
            by_type[t] = by_type.get(t, 0) + 1
        if s := r.get("severity"):
            by_severity[s] = by_severity.get(s, 0) + 1
        d = r.get("decision", "")
        if d:
            by_decision[d] = by_decision.get(d, 0) + 1
        if a := r.get("agent_id"):
            e = agent_map.setdefault(a, {"scan_count": 0, "block_count": 0})
            e["scan_count"] += 1
            if d == "block":
                e["block_count"] += 1

    result = {
        "by_type": sorted([{"_id": k, "count": v} for k, v in by_type.items()], key=lambda x: -x["count"]),
        "by_severity": by_severity,
        "by_decision": by_decision,
        "by_agent": sorted(
            [{"agent_id": a, **v} for a, v in agent_map.items()],
            key=lambda x: -x["scan_count"],
        )[:10],
    }
    await cache_set(cache_key, result, ttl=120)
    return result
