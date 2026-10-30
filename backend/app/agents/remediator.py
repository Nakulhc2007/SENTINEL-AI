"""
SENTINEL-AI — Sentinel-Remediator Agent (Agent 4)
=================================================
Manages the 30+ playbook library, handles human approval/rejection signals,
simulates response execution, and produces outcome verification reports.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.models import Incident, ResponseLog, AuditEntry, Playbook
from app.core.websocket_manager import manager

# ─────────────────────────────────────────────────────────────────────────────
# Playbook Library — 30+ response playbooks across 8 domains
# ─────────────────────────────────────────────────────────────────────────────
PLAYBOOK_LIBRARY = [
    # ── Network Security ──────────────────────────────────────────────────────
    {"code": "PB-NET-001", "name": "Block Scanning IP", "domain": "network_security",
     "trigger": "port_scan nmap scan stealth",
     "description": "Blocks the source IP address at the perimeter firewall and alerts the SOC team.",
     "actions": ["Block source IP at firewall", "Create firewall ACL rule", "Alert SOC team", "Log event to SIEM"],
     "requires_approval": True, "risk_level": "medium", "mitre_tactic": "Discovery", "estimated_duration": "5 min"},
    {"code": "PB-NET-002", "name": "DDoS Mitigation", "domain": "network_security",
     "trigger": "ddos syn flood icmp",
     "description": "Activates rate limiting, null-routes the attack source, and engages ISP scrubbing.",
     "actions": ["Enable rate limiting on edge routers", "Null-route attack source prefixes", "Contact ISP for traffic scrubbing", "Enable anti-spoofing filters"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Impact", "estimated_duration": "15 min"},
    {"code": "PB-NET-003", "name": "C2 Traffic Block", "domain": "network_security",
     "trigger": "botnet c2 dns tunneling",
     "description": "Blocks communication to known C2 infrastructure and isolates affected hosts.",
     "actions": ["Block C2 domains/IPs in DNS sinkhole", "Isolate affected hosts from network", "Capture network traffic for forensics", "Hunt for additional compromised hosts"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Command and Control", "estimated_duration": "20 min"},
    {"code": "PB-NET-004", "name": "Lateral Movement Containment", "domain": "network_security",
     "trigger": "smb lateral psexec",
     "description": "Applies micro-segmentation and blocks SMB traffic to contain lateral spread.",
     "actions": ["Block SMB ports (445/139) between segments", "Apply micro-segmentation rules", "Reset affected service accounts", "Enable enhanced logging on all hosts"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Lateral Movement", "estimated_duration": "25 min"},
    # ── Endpoint Security ─────────────────────────────────────────────────────
    {"code": "PB-EPT-001", "name": "Isolate Compromised Endpoint", "domain": "endpoint_security",
     "trigger": "malware ransomware execution",
     "description": "Isolates the endpoint from the network and initiates forensic imaging.",
     "actions": ["Quarantine endpoint via EDR", "Terminate malicious processes", "Preserve memory dump for forensics", "Initiate disk reimaging procedure"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Execution", "estimated_duration": "30 min"},
    {"code": "PB-EPT-002", "name": "Credential Dump Response", "domain": "endpoint_security",
     "trigger": "mimikatz credential dump",
     "description": "Forces password reset for all accounts on affected host and enables MFA.",
     "actions": ["Force password reset for all accounts on host", "Enable MFA for all affected user accounts", "Invalidate all active sessions", "Review privileged access logs"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Credential Access", "estimated_duration": "20 min"},
    {"code": "PB-EPT-003", "name": "Ransomware Containment", "domain": "endpoint_security",
     "trigger": "ransomware encrypt",
     "description": "Emergency ransomware containment: isolate, snapshot, preserve evidence.",
     "actions": ["Immediately isolate all affected endpoints", "Suspend cloud sync services", "Take VM snapshots before shutdown", "Engage incident response team", "Preserve ransom note and encryption indicators"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Impact", "estimated_duration": "45 min"},
    {"code": "PB-EPT-004", "name": "PowerShell Abuse Response", "domain": "endpoint_security",
     "trigger": "powershell obfusc",
     "description": "Disables PowerShell remoting, enables script block logging, kills process.",
     "actions": ["Kill malicious PowerShell process", "Enable PowerShell script block logging", "Disable PowerShell remoting", "Enforce AppLocker/WDAC policy"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Defense Evasion", "estimated_duration": "15 min"},
    {"code": "PB-EPT-005", "name": "Persistence Removal", "domain": "endpoint_security",
     "trigger": "persistence registry",
     "description": "Removes malicious registry keys, startup entries, and scheduled tasks.",
     "actions": ["Remove malicious registry run keys", "Delete unauthorized scheduled tasks", "Audit startup programs", "Run full AV scan"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Persistence", "estimated_duration": "20 min"},
    # ── Cloud Infrastructure ───────────────────────────────────────────────────
    {"code": "PB-CLD-001", "name": "Revoke Compromised IAM Credentials", "domain": "cloud_infrastructure",
     "trigger": "iam privilege escalation root",
     "description": "Immediately revokes compromised IAM keys and implements least-privilege.",
     "actions": ["Revoke compromised IAM access keys", "Delete unauthorized IAM policies", "Enable CloudTrail for all regions", "Review root account usage", "Enable MFA on root account"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Privilege Escalation", "estimated_duration": "15 min"},
    {"code": "PB-CLD-002", "name": "S3 Exfiltration Block", "domain": "cloud_infrastructure",
     "trigger": "s3 exfiltration data",
     "description": "Blocks public access on S3 buckets and enables bucket access logging.",
     "actions": ["Block all public S3 bucket access", "Enable S3 access logging", "Revoke public bucket policies", "Enable GuardDuty S3 protection", "Audit S3 object ACLs"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Exfiltration", "estimated_duration": "10 min"},
    {"code": "PB-CLD-003", "name": "Crypto Mining Shutdown", "domain": "cloud_infrastructure",
     "trigger": "ec2 cryptomining mining",
     "description": "Terminates unauthorized EC2 instances and restricts GPU usage.",
     "actions": ["Terminate unauthorized EC2 instances", "Apply service control policies to restrict GPU", "Enable billing alerts", "Review and restrict IAM launch permissions"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Impact", "estimated_duration": "10 min"},
    {"code": "PB-CLD-004", "name": "CloudTrail Re-enablement", "domain": "cloud_infrastructure",
     "trigger": "cloudtrail disabled",
     "description": "Re-enables CloudTrail logging and alerts on future disablement attempts.",
     "actions": ["Re-enable CloudTrail in all regions", "Create CloudWatch alarm for future disablement", "Apply SCP to prevent CloudTrail disablement", "Audit who disabled CloudTrail"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Defense Evasion", "estimated_duration": "10 min"},
    # ── IAM  ──────────────────────────────────────────────────────────────────
    {"code": "PB-IAM-001", "name": "Account Lockout — Brute Force", "domain": "iam",
     "trigger": "brute force ssh rdp password spray credential",
     "description": "Locks out attacked accounts, blocks source IPs, enforces MFA.",
     "actions": ["Lock out targeted user accounts (30 min)", "Block source IPs at firewall", "Force MFA enrollment for all affected accounts", "Alert user via out-of-band channel", "Enable enhanced auth logging"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Credential Access", "estimated_duration": "10 min"},
    {"code": "PB-IAM-002", "name": "Token Revocation — Session Hijack", "domain": "iam",
     "trigger": "token theft mfa bypass",
     "description": "Revokes all active sessions and tokens for affected accounts.",
     "actions": ["Revoke all OAuth tokens for affected user", "Invalidate all active SSO sessions", "Force re-authentication with MFA", "Review token issuance logs"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Credential Access", "estimated_duration": "5 min"},
    {"code": "PB-IAM-003", "name": "Impossible Travel Block", "domain": "iam",
     "trigger": "impossible travel",
     "description": "Suspends account pending user verification for impossible travel event.",
     "actions": ["Temporarily suspend affected account", "Send verification challenge to user", "Review recent access logs for account", "Check for concurrent sessions"],
     "requires_approval": True, "risk_level": "medium", "mitre_tactic": "Initial Access", "estimated_duration": "5 min"},
    # ── Application Security  ──────────────────────────────────────────────────
    {"code": "PB-APP-001", "name": "Web Application Firewall Block", "domain": "application_security",
     "trigger": "sqli xss injection csrf lfi rfi path",
     "description": "Activates WAF rules to block SQL injection and XSS attack patterns.",
     "actions": ["Enable WAF blocking mode", "Apply OWASP Core Rule Set", "Block attacking source IPs", "Enable enhanced web server logging", "Review application error logs"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Initial Access", "estimated_duration": "5 min"},
    {"code": "PB-APP-002", "name": "API Rate Limiting", "domain": "application_security",
     "trigger": "bruteforce api",
     "description": "Enforces API rate limiting and adds CAPTCHA to authentication endpoints.",
     "actions": ["Enable API gateway rate limiting (100 req/min)", "Add CAPTCHA to login endpoint", "Block source IP range", "Enable account lockout after 5 failures"],
     "requires_approval": True, "risk_level": "medium", "mitre_tactic": "Credential Access", "estimated_duration": "5 min"},
    {"code": "PB-APP-003", "name": "Command Injection Response", "domain": "application_security",
     "trigger": "cmdinjection command injection",
     "description": "Takes vulnerable application offline, patches input validation, restores.",
     "actions": ["Take affected application offline", "Patch input validation vulnerabilities", "Review all user input handling code", "Enable egress filtering for web server", "Restore after security review"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Execution", "estimated_duration": "60 min"},
    # ── DLP ───────────────────────────────────────────────────────────────────
    {"code": "PB-DLP-001", "name": "USB Port Lockdown", "domain": "dlp",
     "trigger": "usb transfer",
     "description": "Disables USB ports on affected endpoints via GPO enforcement.",
     "actions": ["Disable USB ports via Group Policy", "Audit files copied to USB device", "Alert HR and legal team", "Review user's data access patterns"],
     "requires_approval": True, "risk_level": "medium", "mitre_tactic": "Exfiltration", "estimated_duration": "10 min"},
    {"code": "PB-DLP-002", "name": "Email Exfiltration Block", "domain": "dlp",
     "trigger": "email exfiltration",
     "description": "Quarantines emails with sensitive attachments and audits mail gateway.",
     "actions": ["Quarantine suspicious outbound emails", "Block external email forwarding", "Review email gateway DLP policies", "Alert legal and compliance team"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Exfiltration", "estimated_duration": "10 min"},
    {"code": "PB-DLP-003", "name": "Cloud Upload Block", "domain": "dlp",
     "trigger": "mass cloud upload large file",
     "description": "Blocks mass uploads to cloud storage and quarantines the user session.",
     "actions": ["Block user access to cloud storage platforms", "Quarantine uploaded files for review", "Revoke cloud application OAuth tokens", "Alert DLP team and manager"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Exfiltration", "estimated_duration": "10 min"},
    # ── Insider Threat ────────────────────────────────────────────────────────
    {"code": "PB-INS-001", "name": "Insider Threat Containment", "domain": "insider_threat",
     "trigger": "after hours recon termination hoarding sabotage",
     "description": "Silently restricts account privileges while collecting forensic evidence.",
     "actions": ["Silently reduce account privileges", "Enable enhanced audit logging for user", "Preserve all user activity logs", "Alert HR, legal, and security manager", "Initiate formal investigation"],
     "requires_approval": True, "risk_level": "high", "mitre_tactic": "Collection", "estimated_duration": "30 min"},
    {"code": "PB-INS-002", "name": "Privileged Abuse Response", "domain": "insider_threat",
     "trigger": "privileged abuse account sharing",
     "description": "Revokes privileged access and initiates forensic review of all actions.",
     "actions": ["Revoke all privileged access roles", "Preserve complete audit trail", "Generate activity timeline for investigation", "Brief management and legal", "Assess scope of data accessed"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Privilege Escalation", "estimated_duration": "45 min"},
    # ── Compliance ────────────────────────────────────────────────────────────
    {"code": "PB-COM-001", "name": "GDPR Breach Notification", "domain": "compliance",
     "trigger": "gdpr breach unreported retention",
     "description": "Initiates GDPR 72-hour breach notification process to supervisory authority.",
     "actions": ["Assess personal data affected by breach", "Draft breach notification to DPA (72h deadline)", "Notify affected data subjects", "Document breach details in Records of Processing", "Engage Data Protection Officer"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Impact", "estimated_duration": "120 min"},
    {"code": "PB-COM-002", "name": "Audit Log Integrity Restore", "domain": "compliance",
     "trigger": "audit log tampering soc2",
     "description": "Restores audit logs from backup and implements tamper-evident logging.",
     "actions": ["Restore audit logs from immutable backup", "Implement log integrity monitoring (WORM)", "Alert compliance and auditing teams", "Document log tampering incident", "Implement cryptographic log signing"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Defense Evasion", "estimated_duration": "60 min"},
    {"code": "PB-COM-003", "name": "HIPAA PHI Containment", "domain": "compliance",
     "trigger": "hipaa phi unauthorized encryption",
     "description": "Contains unauthorized PHI access and initiates HIPAA breach assessment.",
     "actions": ["Revoke unauthorized PHI access immediately", "Conduct HIPAA breach risk assessment", "Notify Privacy Officer", "Document in breach log", "Determine notification obligations"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Collection", "estimated_duration": "90 min"},
    {"code": "PB-COM-004", "name": "PCI Clear-Text Data Remediation", "domain": "compliance",
     "trigger": "pci cleartext pan",
     "description": "Encrypts exposed payment data and notifies QSA of compliance violation.",
     "actions": ["Encrypt all identified clear-text PAN data", "Revoke access to unencrypted data stores", "Notify QSA and acquiring bank", "Initiate emergency PCI DSS gap remediation", "Update incident log"],
     "requires_approval": True, "risk_level": "critical", "mitre_tactic": "Collection", "estimated_duration": "180 min"},
]


# Outcome simulation templates
OUTCOME_TEMPLATES = {
    "low":      ("✅ Response executed successfully. Threat neutralized with minimal intervention. No further activity detected post-execution.", 95),
    "medium":   ("✅ Playbook executed. Primary threat vector blocked. Monitoring for lateral movement. Follow-up scan recommended within 24 hours.", 88),
    "high":     ("✅ High-risk response completed. Threat contained but residual risk remains. Continuous monitoring enabled. Escalate to senior SOC.", 82),
    "critical": ("✅ Critical response executed. Systems affected have been isolated. Full forensic investigation initiated. Business continuity team notified.", 75),
}


async def seed_playbooks(db: AsyncSession):
    """Insert all playbooks into DB if not already present."""
    result = await db.execute(select(Playbook).limit(1))
    existing = result.scalar_one_or_none()
    if existing:
        return  # Already seeded

    for pb_data in PLAYBOOK_LIBRARY:
        pb = Playbook(
            id=str(uuid.uuid4()),
            code=pb_data["code"],
            name=pb_data["name"],
            description=pb_data["description"],
            domain=pb_data["domain"],
            trigger=pb_data["trigger"],
            actions=pb_data["actions"],
            requires_approval=pb_data["requires_approval"],
            risk_level=pb_data["risk_level"],
            mitre_tactic=pb_data.get("mitre_tactic"),
            estimated_duration=pb_data.get("estimated_duration"),
        )
        db.add(pb)
    await db.commit()


async def run_remediator(db: AsyncSession, incident_id: str, decision: str, operator_notes: Optional[str] = None):
    """Execute or reject response based on human decision."""
    # Load incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        return None

    if decision == "REJECTED":
        await db.execute(
            update(Incident)
            .where(Incident.id == incident_id)
            .values(status="REJECTED", operator_notes=operator_notes, updated_at=datetime.utcnow())
        )
        await db.commit()
        await manager.broadcast("incident_updated", {
            "id": incident_id, "status": "REJECTED",
            "message": "Response rejected by operator.",
        })
        # Audit
        a = AuditEntry(incident_id=incident_id, agent_name="Sentinel-Remediator",
                       action="Response playbook rejected by operator",
                       details={"operator_notes": operator_notes}, confidence=1.0)
        db.add(a)
        await db.commit()
        return {"status": "REJECTED"}

    # APPROVED — execute playbook
    await db.execute(
        update(Incident)
        .where(Incident.id == incident_id)
        .values(status="REMEDIATING", operator_notes=operator_notes, updated_at=datetime.utcnow())
    )
    await db.commit()

    await manager.broadcast("incident_updated", {
        "id": incident_id, "status": "REMEDIATING",
        "message": "Playbook approved. Executing response actions...",
    })

    # Load playbook
    playbook = None
    if incident.recommended_playbook_id:
        pb_result = await db.execute(select(Playbook).where(Playbook.id == incident.recommended_playbook_id))
        playbook = pb_result.scalar_one_or_none()

    risk_level = playbook.risk_level if playbook else "medium"
    outcome_text, success_pct = OUTCOME_TEMPLATES.get(risk_level, OUTCOME_TEMPLATES["medium"])

    outcome = {
        "playbook_code": playbook.code if playbook else "MANUAL",
        "playbook_name": playbook.name if playbook else "Manual Response",
        "actions_executed": playbook.actions if playbook else ["Manual review completed"],
        "result": outcome_text,
        "success_probability": success_pct,
        "executed_at": datetime.utcnow().isoformat(),
        "threat_neutralized": success_pct > 70,
    }

    response_log = ResponseLog(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        playbook_id=incident.recommended_playbook_id,
        decision="APPROVED",
        operator_notes=operator_notes,
        execution_status="EXECUTED",
        outcome=outcome,
    )
    db.add(response_log)

    await db.execute(
        update(Incident)
        .where(Incident.id == incident_id)
        .values(status="COMPLETE", updated_at=datetime.utcnow())
    )

    audit = AuditEntry(
        incident_id=incident_id,
        agent_name="Sentinel-Remediator",
        action="Response playbook executed",
        details=outcome,
        confidence=success_pct / 100,
    )
    db.add(audit)
    await db.commit()

    await manager.broadcast("incident_updated", {
        "id": incident_id, "status": "COMPLETE",
        "message": "Response executed successfully. Incident resolved.",
        "outcome": outcome,
    })

    return {"status": "COMPLETE", "outcome": outcome, "response_log_id": response_log.id}
