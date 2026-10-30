"""
SENTINEL-AI — Incidents Router
  GET  /api/v1/incidents/            — list incidents
  GET  /api/v1/incidents/{id}        — get incident detail
  POST /api/v1/incidents/{id}/decide — APPROVE or REJECT playbook execution
  POST /api/v1/incidents/{id}/report — trigger auditor for this incident
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.models import Incident, Alert, Playbook, ResponseLog, AuditEntry, Organization

router = APIRouter()


class DecisionPayload(BaseModel):
    decision: str          # "APPROVED" | "REJECTED"
    operator_notes: Optional[str] = None


def _incident_to_dict(inc: Incident, alert: Optional[Alert] = None, playbook: Optional[Playbook] = None) -> dict:
    d = {
        "id": inc.id,
        "org_id": inc.org_id,
        "alert_id": inc.alert_id,
        "title": inc.title,
        "status": inc.status,
        "risk_score": inc.risk_score,
        "root_cause": inc.root_cause,
        "timeline": inc.timeline or [],
        "integrity_status": inc.integrity_status,
        "integrity_original_hash": inc.integrity_original_hash,
        "integrity_current_hash": inc.integrity_current_hash,
        "operator_notes": inc.operator_notes,
        "recommended_playbook_id": inc.recommended_playbook_id,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat(),
    }
    if alert:
        d["alert"] = {
            "id": alert.id,
            "title": alert.title,
            "severity_score": alert.severity_score,
            "confidence": alert.confidence,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
            "mitre_technique_id": alert.mitre_technique_id,
            "attack_type": alert.attack_type,
            "domain": alert.domain,
            "event_count": alert.event_count,
        }
    if playbook:
        d["playbook"] = {
            "id": playbook.id,
            "code": playbook.code,
            "name": playbook.name,
            "description": playbook.description,
            "actions": playbook.actions,
            "risk_level": playbook.risk_level,
            "estimated_duration": playbook.estimated_duration,
            "mitre_tactic": playbook.mitre_tactic,
        }
    return d


@router.get("/stats", summary="Incident statistics")
async def incident_stats(org_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Incident)
    if org_id:
        q = q.where(Incident.org_id == org_id)
    result = await db.execute(q)
    incidents = result.scalars().all()

    total = len(incidents)
    awaiting = sum(1 for i in incidents if i.status == "AWAITING_APPROVAL")
    active   = sum(1 for i in incidents if i.status in ("OPEN", "INVESTIGATING", "REMEDIATING"))
    resolved = sum(1 for i in incidents if i.status == "COMPLETE")
    avg_risk = round(sum(i.risk_score for i in incidents) / total, 1) if total else 0

    return {
        "total": total,
        "awaiting_approval": awaiting,
        "active": active,
        "resolved": resolved,
        "avg_risk_score": avg_risk,
    }


@router.get("/", summary="List all incidents")
async def list_incidents(
    org_id: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident).order_by(desc(Incident.updated_at))
    if org_id:
        q = q.where(Incident.org_id == org_id)
    if status:
        q = q.where(Incident.status == status)
    result = await db.execute(q)
    incidents = result.scalars().all()

    output = []
    for inc in incidents:
        alert_res = await db.execute(select(Alert).where(Alert.id == inc.alert_id))
        alert = alert_res.scalar_one_or_none()
        pb = None
        if inc.recommended_playbook_id:
            pb_res = await db.execute(select(Playbook).where(Playbook.id == inc.recommended_playbook_id))
            pb = pb_res.scalar_one_or_none()
        output.append(_incident_to_dict(inc, alert, pb))
    return output


@router.get("/{incident_id}", summary="Get full incident detail")
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_res = await db.execute(select(Alert).where(Alert.id == inc.alert_id))
    alert = alert_res.scalar_one_or_none()

    pb = None
    if inc.recommended_playbook_id:
        pb_res = await db.execute(select(Playbook).where(Playbook.id == inc.recommended_playbook_id))
        pb = pb_res.scalar_one_or_none()

    # Audit trail
    audit_res = await db.execute(
        select(AuditEntry).where(AuditEntry.incident_id == incident_id).order_by(AuditEntry.timestamp)
    )
    audit_entries = [
        {"agent": a.agent_name, "action": a.action, "confidence": a.confidence, "timestamp": a.timestamp.isoformat()}
        for a in audit_res.scalars().all()
    ]

    d = _incident_to_dict(inc, alert, pb)
    d["audit_trail"] = audit_entries
    return d


@router.post("/{incident_id}/decide", summary="Approve or reject a response playbook")
async def decide_incident(
    incident_id: str,
    payload: DecisionPayload,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status not in ("AWAITING_APPROVAL", "OPEN"):
        raise HTTPException(status_code=400, detail=f"Incident already in status: {inc.status}")

    if payload.decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="Decision must be APPROVED or REJECTED")

    # Run remediator + auditor in background
    from app.agents.remediator import run_remediator
    from app.agents.auditor import run_auditor
    from app.core.database import AsyncSessionLocal
    from app.models.models import Organization

    async def _run(incident_id, decision, notes):
        async with AsyncSessionLocal() as session:
            await run_remediator(session, incident_id, decision, notes)
            if decision == "APPROVED":
                # Get org name for report
                inc_res = await session.execute(select(Incident).where(Incident.id == incident_id))
                inc_obj = inc_res.scalar_one_or_none()
                if inc_obj:
                    org_res = await session.execute(select(Organization).where(Organization.id == inc_obj.org_id))
                    org = org_res.scalar_one_or_none()
                    org_name = org.name if org else "Unknown Organization"
                    await run_auditor(session, incident_id, inc_obj.org_id, org_name)

    background_tasks.add_task(_run, incident_id, payload.decision, payload.operator_notes)

    return {"incident_id": incident_id, "decision": payload.decision, "status": "PROCESSING"}
