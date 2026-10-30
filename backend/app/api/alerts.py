"""
SENTINEL-AI — Alerts Router
  GET /api/v1/alerts/           — list alerts (filter by org, domain, severity)
  GET /api/v1/alerts/stats      — threat stats for dashboard KPIs
  GET /api/v1/alerts/{alert_id} — get single alert
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.core.database import get_db
from app.models.models import Alert

router = APIRouter()


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "org_id": a.org_id,
        "log_id": a.log_id,
        "title": a.title,
        "description": a.description,
        "severity_score": a.severity_score,
        "confidence": a.confidence,
        "mitre_tactic": a.mitre_tactic,
        "mitre_technique": a.mitre_technique,
        "mitre_technique_id": a.mitre_technique_id,
        "attack_type": a.attack_type,
        "domain": a.domain,
        "status": a.status,
        "event_count": a.event_count,
        "created_at": a.created_at.isoformat(),
    }


@router.get("/stats", summary="Threat statistics for dashboard")
async def get_stats(org_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Alert)
    if org_id:
        q = q.where(Alert.org_id == org_id)
    result = await db.execute(q)
    alerts = result.scalars().all()

    total = len(alerts)
    critical = sum(1 for a in alerts if a.severity_score >= 9)
    high     = sum(1 for a in alerts if 7 <= a.severity_score < 9)
    medium   = sum(1 for a in alerts if 4 <= a.severity_score < 7)
    low      = sum(1 for a in alerts if a.severity_score < 4)

    # Domain breakdown
    domain_counts: dict = {}
    for a in alerts:
        domain_counts[a.domain] = domain_counts.get(a.domain, 0) + 1

    # MITRE tactic breakdown
    tactic_counts: dict = {}
    for a in alerts:
        if a.mitre_tactic:
            tactic_counts[a.mitre_tactic] = tactic_counts.get(a.mitre_tactic, 0) + 1

    avg_confidence = round(sum(a.confidence for a in alerts) / total, 1) if total else 0

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "avg_confidence": avg_confidence,
        "domain_breakdown": domain_counts,
        "tactic_breakdown": tactic_counts,
    }


@router.get("/", summary="List all alerts")
async def list_alerts(
    org_id: Optional[str] = None,
    domain: Optional[str] = None,
    min_severity: Optional[float] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if org_id:
        q = q.where(Alert.org_id == org_id)
    if domain:
        q = q.where(Alert.domain == domain)
    if min_severity is not None:
        q = q.where(Alert.severity_score >= min_severity)
    if status:
        q = q.where(Alert.status == status)
    result = await db.execute(q)
    return [_alert_to_dict(a) for a in result.scalars().all()]


@router.get("/{alert_id}", summary="Get a specific alert")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    a = result.scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(a)
