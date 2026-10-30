"""
SENTINEL-AI — Sentinel-Investigator Agent (Agent 3)
===================================================
For each Alert, opens an Incident, builds a chronological event timeline,
calculates an explainable risk score (0-100), verifies SHA-256 file integrity,
and generates a root-cause hypothesis using template-based reasoning.
"""
import hashlib
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.models import (
    Alert, Incident, NormalizedEvent, SecurityLog, AuditEntry, Playbook
)
from app.core.websocket_manager import manager

# Domain criticality weights (higher = more critical)
DOMAIN_WEIGHT = {
    "network_security":    1.2,
    "endpoint_security":   1.3,
    "cloud_infrastructure": 1.4,
    "iam":                 1.35,
    "application_security": 1.1,
    "dlp":                 1.25,
    "insider_threat":      1.3,
    "compliance":          1.0,
}

# Root-cause hypothesis templates per tactic
ROOT_CAUSE_TEMPLATES = {
    "Initial Access": (
        "Analysis indicates a likely initial access attempt targeting {domain} infrastructure. "
        "The threat actor appears to have exploited {attack_type} vulnerability to gain unauthorized entry. "
        "Evidence from {event_count} correlated events suggests a systematic exploitation pattern "
        "consistent with MITRE ATT&CK technique {mitre_id} ({mitre_name}). "
        "Immediate containment is recommended to prevent lateral movement."
    ),
    "Credential Access": (
        "The investigation reveals a credential access campaign against {domain} systems. "
        "Attack pattern '{attack_type}' was identified across {event_count} events, "
        "indicating the threat actor is attempting to harvest valid credentials. "
        "This aligns with MITRE technique {mitre_id}. "
        "Accounts involved should be temporarily suspended pending verification."
    ),
    "Lateral Movement": (
        "Lateral movement activity has been detected within {domain} systems. "
        "The attacker appears to have leveraged {attack_type} to traverse the network, "
        "with {event_count} events recorded across multiple hosts. "
        "MITRE technique {mitre_id} ({mitre_name}) is the most likely vector. "
        "Network segmentation enforcement is urgently recommended."
    ),
    "Exfiltration": (
        "Data exfiltration indicators have been identified in {domain} logs. "
        "Technique '{attack_type}' was used across {event_count} data transfer events, "
        "suggesting sensitive data may have been exfiltrated. "
        "MITRE technique {mitre_id} ({mitre_name}) aligns with observed behavior. "
        "Immediate DLP policy enforcement and egress filtering are advised."
    ),
    "Execution": (
        "Malicious code execution has been detected on {domain} systems. "
        "The threat involves '{attack_type}' activity across {event_count} process events. "
        "This corresponds to MITRE technique {mitre_id} ({mitre_name}). "
        "Affected endpoints should be isolated and forensic imaging initiated immediately."
    ),
    "Defense Evasion": (
        "Defense evasion techniques have been observed in {domain} environment. "
        "The attacker employed '{attack_type}' across {event_count} events to avoid detection. "
        "Per MITRE technique {mitre_id} ({mitre_name}), the attacker is actively attempting "
        "to disable or bypass security controls. Review security tool configurations immediately."
    ),
    "Impact": (
        "High-impact destructive activity has been identified in {domain} systems. "
        "Attack type '{attack_type}' recorded {event_count} critical events indicating "
        "system availability or data integrity is at risk. "
        "MITRE technique {mitre_id} ({mitre_name}) confirms the destructive intent. "
        "Isolate affected systems and initiate business continuity procedures."
    ),
    "Persistence": (
        "Persistence mechanisms have been established in {domain} infrastructure. "
        "The threat actor used '{attack_type}' across {event_count} events to maintain "
        "long-term access. This matches MITRE technique {mitre_id} ({mitre_name}). "
        "Conduct full host forensics, remove persistence artifacts, and rotate all credentials."
    ),
    "Command and Control": (
        "Command and control (C2) communication has been detected from {domain} systems. "
        "The '{attack_type}' traffic pattern spans {event_count} network events, "
        "suggesting active attacker communication via MITRE technique {mitre_id} ({mitre_name}). "
        "Block identified C2 endpoints and initiate threat hunting across the network."
    ),
    "Discovery": (
        "Reconnaissance and discovery activity observed in {domain} environment. "
        "Technique '{attack_type}' generated {event_count} events consistent with "
        "an attacker mapping the internal network per MITRE {mitre_id} ({mitre_name}). "
        "Review access logs for subsequent exploitation attempts."
    ),
    "Collection": (
        "Data collection activity detected in {domain} systems. "
        "'{attack_type}' was used across {event_count} events to aggregate sensitive data, "
        "per MITRE technique {mitre_id} ({mitre_name}). "
        "Audit data access logs and enforce data classification policies."
    ),
    "Privilege Escalation": (
        "Privilege escalation attempt detected in {domain} environment. "
        "Attack type '{attack_type}' observed across {event_count} events suggests "
        "an attacker is gaining elevated access privileges per MITRE {mitre_id} ({mitre_name}). "
        "Review IAM policies and enforce least-privilege access controls immediately."
    ),
}

DEFAULT_ROOT_CAUSE = (
    "Anomalous activity of type '{attack_type}' was detected across {event_count} security events "
    "in the {domain} domain (MITRE: {mitre_id} — {mitre_name}). "
    "Risk score of {risk_score}/100 reflects severity {severity_label} classification and "
    "domain criticality weighting. Investigation is ongoing; apply recommended playbook and "
    "monitor for follow-on activity."
)


def generate_root_cause(alert: Alert, risk_score: int, event_count: int) -> str:
    template = ROOT_CAUSE_TEMPLATES.get(alert.mitre_tactic or "", DEFAULT_ROOT_CAUSE)
    return template.format(
        domain=alert.domain.replace("_", " ").title(),
        attack_type=alert.attack_type or "Unknown",
        event_count=event_count,
        mitre_id=alert.mitre_technique_id or "T1190",
        mitre_name=alert.mitre_technique or "Unknown Technique",
        risk_score=risk_score,
        severity_label=["info", "low", "medium", "high", "critical"][
            min(4, max(0, int(alert.severity_score / 2)))
        ],
    )


def calculate_risk_score(alert: Alert, event_count: int) -> int:
    """
    Risk formula:
        risk = min(100, severity_score * 10 * domain_weight * recency_multiplier * blast_radius)
    """
    severity_factor  = alert.severity_score * 10.0
    domain_weight    = DOMAIN_WEIGHT.get(alert.domain, 1.0)
    blast_radius     = 1.0 + min(event_count / 20.0, 1.0)
    # Recency: incidents in last 24h get 1.1x boost
    hours_ago        = (datetime.utcnow() - alert.created_at).total_seconds() / 3600
    recency          = 1.1 if hours_ago < 24 else 1.0
    raw              = severity_factor * domain_weight * blast_radius * recency
    return min(100, int(raw))


async def find_matching_playbook(db: AsyncSession, alert: Alert) -> Optional[str]:
    result = await db.execute(
        select(Playbook).where(Playbook.domain == alert.domain)
    )
    playbooks = result.scalars().all()
    if not playbooks:
        return None
    # Try to match by attack type keyword in trigger
    attack = (alert.attack_type or "").lower()
    for pb in playbooks:
        if any(kw in pb.trigger.lower() for kw in attack.split("-") + attack.split("_")):
            return pb.id
    # Fallback: highest risk_level playbook in domain
    priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    playbooks_sorted = sorted(playbooks, key=lambda p: priority.get(p.risk_level, 0), reverse=True)
    return playbooks_sorted[0].id if playbooks_sorted else None


async def run_investigator(db: AsyncSession, log_id: str, org_id: str, alert_ids: list[str]):
    """Build incidents for each alert with timeline, risk score, and root cause."""
    await manager.broadcast("pipeline_progress", {
        "log_id": log_id,
        "stage": "INVESTIGATING",
        "message": "Sentinel-Investigator: Building incident timelines and risk scores...",
    })

    # Load the log to get original hash
    log_result = await db.execute(select(SecurityLog).where(SecurityLog.id == log_id))
    log_obj = log_result.scalar_one_or_none()
    original_hash = log_obj.sha256_hash if log_obj else None

    incident_records = []

    for alert_id in alert_ids:
        alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = alert_result.scalar_one_or_none()
        if not alert:
            continue

        # Load correlated events
        event_ids = alert.event_ids or []
        events = []
        if event_ids:
            ev_result = await db.execute(
                select(NormalizedEvent).where(NormalizedEvent.id.in_(event_ids[:20]))
            )
            events = ev_result.scalars().all()

        # Build timeline
        timeline = []
        for ev in sorted(events, key=lambda e: e.timestamp or ""):
            timeline.append({
                "timestamp": ev.timestamp,
                "action": ev.action,
                "src_ip": ev.src_ip,
                "dst_ip": ev.dst_ip,
                "severity_label": ev.severity_label,
                "attack_type": ev.attack_type,
                "hostname": ev.hostname,
                "username": ev.username,
                "description": f"{ev.action} from {ev.src_ip or 'N/A'} to {ev.dst_ip or 'N/A'}",
            })

        # Fill timeline if empty (from alert metadata)
        if not timeline:
            timeline = [{
                "timestamp": alert.created_at.isoformat(),
                "action": f"{alert.attack_type} activity detected",
                "src_ip": None,
                "dst_ip": None,
                "severity_label": ["info","low","medium","high","critical"][min(4, int(alert.severity_score/2))],
                "attack_type": alert.attack_type,
                "description": alert.description,
            }]

        risk_score     = calculate_risk_score(alert, alert.event_count)
        root_cause     = generate_root_cause(alert, risk_score, alert.event_count)
        playbook_id    = await find_matching_playbook(db, alert)

        # SHA-256 integrity check (file is already parsed; re-confirm hash matches)
        import os
        from app.core.config import settings
        integrity_status = "PENDING"
        current_hash     = original_hash
        if log_obj and log_obj.stored_filename:
            file_path = os.path.join(settings.UPLOAD_DIR, log_obj.stored_filename)
            if os.path.exists(file_path):
                h = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                current_hash = h.hexdigest()
                integrity_status = "VERIFIED" if current_hash == original_hash else "TAMPERED"

        incident = Incident(
            id=str(uuid.uuid4()),
            org_id=org_id,
            alert_id=alert_id,
            title=f"INC — {alert.title}",
            status="AWAITING_APPROVAL",
            risk_score=risk_score,
            timeline=timeline,
            root_cause=root_cause,
            integrity_status=integrity_status,
            integrity_original_hash=original_hash,
            integrity_current_hash=current_hash,
            recommended_playbook_id=playbook_id,
        )
        db.add(incident)
        incident_records.append(incident)

        # Audit entry
        audit = AuditEntry(
            incident_id=incident.id,
            log_id=log_id,
            agent_name="Sentinel-Investigator",
            action="Incident created with timeline and risk score",
            details={
                "risk_score": risk_score,
                "timeline_events": len(timeline),
                "integrity_status": integrity_status,
                "playbook_matched": playbook_id is not None,
            },
            confidence=0.94,
        )
        db.add(audit)

    await db.commit()

    # Broadcast incident updates
    for inc in incident_records:
        await manager.broadcast("incident_updated", {
            "id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "risk_score": inc.risk_score,
            "alert_id": inc.alert_id,
            "integrity_status": inc.integrity_status,
            "created_at": inc.created_at.isoformat(),
        })

    await manager.broadcast("pipeline_progress", {
        "log_id": log_id,
        "stage": "INVESTIGATED",
        "message": f"Sentinel-Investigator: Created {len(incident_records)} incidents. Awaiting human approval.",
        "incidents": len(incident_records),
    })

    return incident_records
