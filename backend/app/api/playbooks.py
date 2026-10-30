"""
SENTINEL-AI — Playbooks, Reports, Audit Routers
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.models import Playbook, Report, AuditEntry

# ── Playbooks ─────────────────────────────────────────────────────────────────
router = APIRouter()

@router.get("/", summary="List all playbooks")
async def list_playbooks(domain: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Playbook).order_by(Playbook.code)
    if domain:
        q = q.where(Playbook.domain == domain)
    result = await db.execute(q)
    pbs = result.scalars().all()
    return [
        {
            "id": pb.id, "code": pb.code, "name": pb.name,
            "description": pb.description, "domain": pb.domain,
            "actions": pb.actions, "risk_level": pb.risk_level,
            "requires_approval": pb.requires_approval,
            "mitre_tactic": pb.mitre_tactic,
            "estimated_duration": pb.estimated_duration,
        }
        for pb in pbs
    ]

@router.get("/{playbook_id}", summary="Get a specific playbook")
async def get_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"id": pb.id, "code": pb.code, "name": pb.name, "description": pb.description,
            "domain": pb.domain, "actions": pb.actions, "risk_level": pb.risk_level,
            "requires_approval": pb.requires_approval, "mitre_tactic": pb.mitre_tactic,
            "estimated_duration": pb.estimated_duration}
