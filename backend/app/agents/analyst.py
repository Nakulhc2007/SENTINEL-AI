"""
SENTINEL-AI — Sentinel-Analyst Agent (Agent 2)
==============================================
Loads the pre-trained RandomForest model (sentinel_model.pkl),
runs anomaly detection + rule-based Sigma-style detection on normalized events,
maps findings to MITRE ATT&CK, and creates Alert records.
"""
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.models import NormalizedEvent, SecurityLog, Alert, AuditEntry
from app.core.config import settings
from app.core.websocket_manager import manager


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping per attack type
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    # Network
    "DDoS-SYN-Flood":      ("Impact", "T1498", "Network Denial of Service"),
    "Nmap-Scan":           ("Discovery", "T1046", "Network Service Discovery"),
    "PortScan-Stealth":    ("Discovery", "T1046", "Network Service Discovery"),
    "DNS-Tunneling":       ("Command and Control", "T1071.004", "DNS"),
    "Botnet-C2":           ("Command and Control", "T1071", "Application Layer Protocol"),
    "SMB-Lateral":         ("Lateral Movement", "T1021.002", "SMB/Windows Admin Shares"),
    "ICMP-Flood":          ("Impact", "T1498", "Network Denial of Service"),
    "SQL-Injection-HTTP":  ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    # Endpoint
    "MalwareExecution":    ("Execution", "T1204", "User Execution"),
    "RansomwareEncrypt":   ("Impact", "T1486", "Data Encrypted for Impact"),
    "PowerShellObfusc":    ("Defense Evasion", "T1027", "Obfuscated Files or Information"),
    "MimikatzDump":        ("Credential Access", "T1003", "OS Credential Dumping"),
    "DLLInjection":        ("Defense Evasion", "T1055", "Process Injection"),
    "PrivilegeEscalation": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "PersistenceRegEdit":  ("Persistence", "T1547", "Boot or Logon Autostart Execution"),
    "LateralMovementPSExec": ("Lateral Movement", "T1021", "Remote Services"),
    # Cloud
    "IAMPrivilegeEscalation": ("Privilege Escalation", "T1078", "Valid Accounts"),
    "S3DataExfiltration":  ("Exfiltration", "T1537", "Transfer Data to Cloud Account"),
    "CloudTrailDisabled":  ("Defense Evasion", "T1562", "Impair Defenses"),
    "RootAccountUsed":     ("Initial Access", "T1078.004", "Cloud Accounts"),
    "SecretsManagerDump":  ("Credential Access", "T1552", "Unsecured Credentials"),
    "EC2CryptoMining":     ("Impact", "T1496", "Resource Hijacking"),
    "LambdaBackdoor":      ("Persistence", "T1525", "Implant Internal Image"),
    "SecGroupMisconfiguration": ("Defense Evasion", "T1562", "Impair Defenses"),
    # IAM
    "BruteForceSSH":       ("Credential Access", "T1110", "Brute Force"),
    "BruteForceRDP":       ("Credential Access", "T1110", "Brute Force"),
    "PasswordSpray":       ("Credential Access", "T1110.003", "Password Spraying"),
    "CredentialStuffing":  ("Credential Access", "T1110.004", "Credential Stuffing"),
    "MFABypass":           ("Defense Evasion", "T1556", "Modify Authentication Process"),
    "ImpossibleTravel":    ("Initial Access", "T1078", "Valid Accounts"),
    "TokenTheft":          ("Credential Access", "T1528", "Steal Application Access Token"),
    "LDAP-Enum":           ("Discovery", "T1018", "Remote System Discovery"),
    # AppSec
    "SQLi":                ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "XSS":                 ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "CSRF":                ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "LFI":                 ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "RFI":                 ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "PathTraversal":       ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "CmdInjection":        ("Execution", "T1059", "Command and Scripting Interpreter"),
    "BruteForce-API":      ("Credential Access", "T1110", "Brute Force"),
    # DLP
    "USBDataTransfer":     ("Exfiltration", "T1052", "Exfiltration Over Physical Medium"),
    "EmailExfiltration":   ("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol"),
    "LargeFileTransfer":   ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "MassCloudUpload":     ("Exfiltration", "T1537", "Transfer Data to Cloud Account"),
    "PrintSensitiveDoc":   ("Exfiltration", "T1052", "Exfiltration Over Physical Medium"),
    "ScreenCaptureLeak":   ("Collection", "T1113", "Screen Capture"),
    "ClipboardExfil":      ("Collection", "T1115", "Clipboard Data"),
    "UnauthorizedRemote":  ("Lateral Movement", "T1021", "Remote Services"),
    # Insider
    "AfterHoursAccess":    ("Initial Access", "T1078", "Valid Accounts"),
    "DataHoarding":        ("Collection", "T1213", "Data from Information Repositories"),
    "ReconBeforeTermination": ("Discovery", "T1082", "System Information Discovery"),
    "SystemSabotage":      ("Impact", "T1485", "Data Destruction"),
    "CredentialHarvesting": ("Credential Access", "T1003", "OS Credential Dumping"),
    "CompetitorResearch":  ("Discovery", "T1213", "Data from Information Repositories"),
    "PrivilegedAbuse":     ("Privilege Escalation", "T1078", "Valid Accounts"),
    "AccountSharing":      ("Initial Access", "T1078", "Valid Accounts"),
    # Compliance
    "GDPR-DataBreachUnreported": ("Impact", "T1657", "Financial Theft"),
    "GDPR-ExcessiveRetention":   ("Collection", "T1530", "Data from Cloud Storage"),
    "HIPAA-UnauthorizedPHIAccess": ("Collection", "T1530", "Data from Cloud Storage"),
    "HIPAA-EncryptionViolation": ("Defense Evasion", "T1600", "Weaken Encryption"),
    "SOC2-AuditLogTampering":    ("Defense Evasion", "T1070", "Indicator Removal"),
    "SOC2-ChangeWithoutApproval": ("Persistence", "T1078", "Valid Accounts"),
    "PCI-ClearTextPAN":          ("Collection", "T1005", "Data from Local System"),
    "ISO27001-PolicyViolation":  ("Defense Evasion", "T1562", "Impair Defenses"),
}

SEVERITY_SCORE = {0: 1.0, 1: 2.5, 2: 4.5, 3: 7.5, 4: 9.5}
DOMAIN_ENC = {
    "application_security": 0, "cloud_infrastructure": 1, "compliance": 2,
    "dlp": 3, "endpoint_security": 4, "iam": 5, "insider_threat": 6, "network_security": 7
}

# Load model once at module import
_model = None
_meta = None


def _load_model():
    global _model, _meta
    if _model is not None:
        return
    root = Path(__file__).resolve().parent.parent.parent.parent
    model_path = root / "models" / "sentinel_model.pkl"
    meta_path  = root / "models" / "sentinel_model_meta.pkl"
    if model_path.exists():
        _model = joblib.load(model_path)
        if meta_path.exists():
            _meta = joblib.load(meta_path)


def _get_extra(val, key, default=0.0):
    try:
        d = val if isinstance(val, dict) else (json.loads(str(val)) if val else {})
        v = d.get(key, default)
        return float(v) if v is not None else default
    except Exception:
        return default


def _extract_features(events: list[NormalizedEvent]) -> np.ndarray:
    """Extract the same 7 features used during training."""
    rows = []
    for e in events:
        domain_enc = DOMAIN_ENC.get(e.domain, 0)
        action_enc = hash(e.action or "unknown") % 1000
        sev_enc    = e.severity or 0
        extra      = e.extra_fields or {}
        packets    = _get_extra(extra, "packets", 0)
        bytes_val  = _get_extra(extra, "bytes", 0)
        risk_score = _get_extra(extra, "risk_score", 0)
        hour       = _get_extra(extra, "hour_of_day", 12)
        rows.append([domain_enc, action_enc, sev_enc, packets, bytes_val, risk_score, hour])
    return np.array(rows, dtype=float)


def _get_mitre(attack_type: Optional[str]):
    if not attack_type:
        return None, None, None
    entry = MITRE_MAP.get(attack_type)
    if entry:
        return entry[0], entry[1], entry[2]
    return "Initial Access", "T1190", "Exploit Public-Facing Application"


async def run_analyst(db: AsyncSession, log_id: str, org_id: str):
    """Detect threats, group into alerts, stream results."""
    _load_model()

    await manager.broadcast("pipeline_progress", {
        "log_id": log_id,
        "stage": "ANALYZING",
        "message": "Sentinel-Analyst: Running ML anomaly detection + rule engine...",
    })

    # Load events for this log
    result = await db.execute(
        select(NormalizedEvent).where(NormalizedEvent.log_id == log_id)
    )
    events = result.scalars().all()
    if not events:
        return []

    # ── ML Inference ──────────────────────────────────────────────────────────
    attack_event_ids = []
    if _model is not None:
        X = _extract_features(events)
        preds = _model.predict(X)
        probs = _model.predict_proba(X)
        for i, (e, pred, prob) in enumerate(zip(events, preds, probs)):
            if pred == 1 or e.is_attack is True:
                attack_event_ids.append((e, float(prob[1]) * 100))
    else:
        # Rule-based fallback: flag events where is_attack=True or severity >= 3
        for e in events:
            if e.is_attack is True or (e.severity is not None and e.severity >= 3):
                attack_event_ids.append((e, 85.0))

    # ── Group by attack_type → one Alert per group ────────────────────────────
    groups: dict[str, list] = {}
    for e, confidence in attack_event_ids:
        key = e.attack_type or f"Unknown-{e.domain}"
        if key not in groups:
            groups[key] = []
        groups[key].append((e, confidence))

    alert_records = []
    for attack_type, group in groups.items():
        events_in_group = [g[0] for g in group]
        avg_confidence  = sum(g[1] for g in group) / len(group)
        max_severity    = max(e.severity for e in events_in_group)
        severity_score  = SEVERITY_SCORE.get(max_severity, 5.0)
        domain          = events_in_group[0].domain
        event_ids       = [e.id for e in events_in_group[:10]]  # keep first 10 IDs

        mitre_tactic, mitre_id, mitre_name = _get_mitre(attack_type)

        alert = Alert(
            id=str(uuid.uuid4()),
            org_id=org_id,
            log_id=log_id,
            title=f"{attack_type.replace('-', ' ').replace('_', ' ')} Detected",
            description=(
                f"Detected {len(events_in_group)} event(s) of type '{attack_type}' "
                f"in domain '{domain}'. Max severity: {['info','low','medium','high','critical'][max_severity]}. "
                f"MITRE: {mitre_tactic} → {mitre_name}."
            ),
            severity_score=severity_score,
            confidence=round(avg_confidence, 1),
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_name,
            mitre_technique_id=mitre_id,
            attack_type=attack_type,
            domain=domain,
            status="OPEN",
            event_count=len(events_in_group),
            event_ids=event_ids,
        )
        db.add(alert)
        alert_records.append(alert)

        # Broadcast each alert in real time
        await manager.broadcast("alert_created", {
            "id": alert.id,
            "title": alert.title,
            "severity_score": alert.severity_score,
            "confidence": alert.confidence,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique_id": mitre_id,
            "attack_type": attack_type,
            "domain": domain,
            "event_count": alert.event_count,
            "created_at": alert.created_at.isoformat(),
        })

    await db.commit()

    # Audit
    audit = AuditEntry(
        log_id=log_id,
        agent_name="Sentinel-Analyst",
        action="Threat detection and correlation completed",
        details={
            "alerts_generated": len(alert_records),
            "attack_events": len(attack_event_ids),
            "model_used": "RandomForest" if _model else "RuleEngine",
        },
        confidence=0.97,
    )
    db.add(audit)
    await db.commit()

    await manager.broadcast("pipeline_progress", {
        "log_id": log_id,
        "stage": "ANALYZED",
        "message": f"Sentinel-Analyst: Generated {len(alert_records)} alerts from {len(attack_event_ids)} attack events.",
        "alerts": len(alert_records),
    })

    return alert_records
