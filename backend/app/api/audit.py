"""
SENTINEL-AI — Audit Trail Router
  GET /api/v1/audit/              — full audit log (paginated)
  GET /api/v1/audit/{incident_id} — audit entries for specific incident
"""
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.models import AuditEntry

router = APIRouter()


def _audit_to_dict(a: AuditEntry) -> dict:
    return {
        "id": a.id,
        "incident_id": a.incident_id,
        "log_id": a.log_id,
        "agent_name": a.agent_name,
        "action": a.action,
        "details": a.details,
        "confidence": a.confidence,
        "timestamp": a.timestamp.isoformat(),
    }


@router.get("/", summary="Full audit trail (most recent first)")
async def list_audit(
    limit: int = 100,
    incident_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(AuditEntry).order_by(desc(AuditEntry.timestamp)).limit(limit)
    if incident_id:
        q = q.where(AuditEntry.incident_id == incident_id)
    result = await db.execute(q)
    return [_audit_to_dict(a) for a in result.scalars().all()]


@router.get("/incident/{incident_id}", summary="Audit entries for one incident")
async def audit_for_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditEntry).where(AuditEntry.incident_id == incident_id).order_by(AuditEntry.timestamp)
    )
    return [_audit_to_dict(a) for a in result.scalars().all()]
