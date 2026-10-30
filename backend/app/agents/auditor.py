"""
SENTINEL-AI — Sentinel-Auditor Agent (Agent 5)
==============================================
Compiles all agent outputs into a PDF investigation report (ReportLab),
maps incidents to GDPR / HIPAA / SOC 2 / ISO 27001 compliance frameworks,
and appends a tamper-evident audit trail entry.
"""
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.models.models import Incident, Alert, AuditEntry, Report, Playbook, ResponseLog
from app.core.config import settings
from app.core.websocket_manager import manager

# ─────────────────────────────────────────────────────────────────────────────
# Compliance Framework Mapping
# ─────────────────────────────────────────────────────────────────────────────
COMPLIANCE_MAP = {
    "network_security": {
        "GDPR": ["Art. 32 — Security of Processing"],
        "HIPAA": ["164.312(e)(2)(ii) — Encryption in Transit"],
        "SOC2": ["CC6.7 — Logical Access", "CC7.2 — Monitoring"],
        "ISO27001": ["A.13 — Communications Security"],
    },
    "endpoint_security": {
        "GDPR": ["Art. 32 — Security of Processing", "Art. 25 — Privacy by Design"],
        "HIPAA": ["164.312(a)(2)(iv) — Encryption", "164.312(b) — Audit Controls"],
        "SOC2": ["CC6.8 — Malware Prevention", "CC7.1 — Threat Detection"],
        "ISO27001": ["A.12.2 — Malware Protection", "A.12.6 — Vulnerability Management"],
    },
    "cloud_infrastructure": {
        "GDPR": ["Art. 32 — Security of Processing", "Art. 28 — Processor Agreements"],
        "HIPAA": ["164.312(a)(1) — Access Control", "164.308(a)(1) — Risk Analysis"],
        "SOC2": ["CC6.1 — Logical Access", "A1.2 — Availability"],
        "ISO27001": ["A.15 — Supplier Relationships", "A.12.3 — Information Backup"],
    },
    "iam": {
        "GDPR": ["Art. 5(1)(f) — Integrity and Confidentiality", "Art. 32 — Security"],
        "HIPAA": ["164.312(a)(1) — Access Control", "164.312(d) — Person Authentication"],
        "SOC2": ["CC6.2 — Prior Access Authorization", "CC6.3 — Role-Based Access"],
        "ISO27001": ["A.9 — Access Control", "A.9.4 — System and Application Access"],
    },
    "application_security": {
        "GDPR": ["Art. 32 — Security of Processing", "Art. 25 — Data Protection by Design"],
        "HIPAA": ["164.312(c)(1) — Integrity Controls"],
        "SOC2": ["CC8.1 — Change Management", "CC7.1 — Threat Detection"],
        "ISO27001": ["A.14 — System Acquisition and Development", "A.14.2 — Secure Development"],
    },
    "dlp": {
        "GDPR": ["Art. 5(1)(e) — Storage Limitation", "Art. 32 — Security of Processing"],
        "HIPAA": ["164.308(a)(4) — Information Access Management", "164.310(d)(1) — Device Controls"],
        "SOC2": ["CC6.7 — Transmission Restrictions", "P5 — Privacy"],
        "ISO27001": ["A.13.2 — Information Transfer", "A.18.1 — Compliance with Legal Requirements"],
    },
    "insider_threat": {
        "GDPR": ["Art. 32 — Security of Processing", "Art. 5(1)(f) — Confidentiality"],
        "HIPAA": ["164.308(a)(3) — Workforce Security", "164.308(a)(6) — Incident Procedures"],
        "SOC2": ["CC1.4 — Board Oversight", "CC2.3 — Communication"],
        "ISO27001": ["A.7 — Human Resource Security", "A.16 — Incident Management"],
    },
    "compliance": {
        "GDPR": ["Art. 33 — Breach Notification", "Art. 83 — Fines"],
        "HIPAA": ["164.308(a)(6) — Security Incident Procedures", "164.414 — Response and Reporting"],
        "SOC2": ["CC4.1 — Risk Assessment", "CC9.2 — Risk Mitigation"],
        "ISO27001": ["A.18 — Compliance", "A.18.1 — Legal Requirements"],
    },
}


def _get_compliance(domain: str) -> dict:
    return COMPLIANCE_MAP.get(domain, {
        "GDPR": ["Art. 32 — Security of Processing"],
        "HIPAA": ["164.308(a)(1) — Risk Analysis"],
        "SOC2": ["CC7.1 — Threat Detection"],
        "ISO27001": ["A.16 — Incident Management"],
    })


def _risk_color(risk_score: int):
    if risk_score >= 80:
        return colors.HexColor("#FF2D55")
    elif risk_score >= 60:
        return colors.HexColor("#FF9500")
    elif risk_score >= 40:
        return colors.HexColor("#FFCC00")
    return colors.HexColor("#34C759")


def generate_pdf(incident: Incident, alert: Alert, audit_entries: list,
                 response_logs: list, playbook: Optional[Playbook],
                 org_name: str, output_path: str) -> str:
    """Generate a fully styled PDF investigation report using ReportLab."""
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm
    )
    styles     = getSampleStyleSheet()
    brand_dark = colors.HexColor("#0A0F1E")
    brand_cyan = colors.HexColor("#00D4FF")
    brand_red  = colors.HexColor("#FF2D55")

    h1   = ParagraphStyle("h1",   parent=styles["Heading1"],  fontSize=22, textColor=brand_cyan,  spaceAfter=4)
    h2   = ParagraphStyle("h2",   parent=styles["Heading2"],  fontSize=13, textColor=brand_cyan,  spaceAfter=3)
    body = ParagraphStyle("body", parent=styles["Normal"],    fontSize=9,  textColor=colors.black, leading=14)
    mono = ParagraphStyle("mono", parent=styles["Code"],      fontSize=8,  textColor=colors.HexColor("#333"),leading=12)
    sub  = ParagraphStyle("sub",  parent=styles["Normal"],    fontSize=8,  textColor=colors.gray)
    bold = ParagraphStyle("bold", parent=styles["Normal"],    fontSize=9,  fontName="Helvetica-Bold")

    elements = []

    # ── Header Banner ─────────────────────────────────────────────────────────
    elements.append(Paragraph("🛡 SENTINEL-AI — SECURITY INVESTIGATION REPORT", h1))
    elements.append(Paragraph(f"Team: SYNTHETIX &nbsp;|&nbsp; Team ID: AH-45 &nbsp;|&nbsp; AfterHours 1.0 Hackathon", sub))
    elements.append(HRFlowable(width="100%", thickness=2, color=brand_cyan, spaceAfter=8))

    # ── Incident Summary ──────────────────────────────────────────────────────
    elements.append(Paragraph("1. Incident Summary", h2))
    risk_col = _risk_color(incident.risk_score)
    summary_data = [
        ["Incident ID",    incident.id],
        ["Organization",   org_name],
        ["Status",         incident.status],
        ["Risk Score",     f"{incident.risk_score} / 100"],
        ["Severity",       f"{alert.severity_score:.1f} / 10"],
        ["Confidence",     f"{alert.confidence:.1f}%"],
        ["Domain",         alert.domain.replace("_", " ").title()],
        ["Attack Type",    alert.attack_type or "N/A"],
        ["MITRE Tactic",   alert.mitre_tactic or "N/A"],
        ["MITRE ID",       f"{alert.mitre_technique_id or 'N/A'} — {alert.mitre_technique or 'N/A'}"],
        ["Events Affected",str(alert.event_count)],
        ["Integrity",      incident.integrity_status or "PENDING"],
        ["Created",        incident.created_at.strftime("%Y-%m-%d %H:%M UTC")],
    ]
    t = Table(summary_data, colWidths=[55*mm, 120*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#E8F4FD")),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, colors.HexColor("#F9F9F9")]),
        ("TEXTCOLOR",   (1, 3), (1, 3), risk_col if incident.risk_score >= 60 else colors.black),
        ("FONTNAME",    (1, 3), (1, 3), "Helvetica-Bold"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    elements += [t, Spacer(1, 6*mm)]

    # ── Root Cause ────────────────────────────────────────────────────────────
    elements.append(Paragraph("2. Root Cause Analysis", h2))
    elements.append(Paragraph(incident.root_cause or "Analysis in progress.", body))
    elements.append(Spacer(1, 4*mm))

    # ── Timeline ──────────────────────────────────────────────────────────────
    elements.append(Paragraph("3. Event Timeline", h2))
    timeline = incident.timeline or []
    if timeline:
        tl_data = [["Timestamp", "Action", "Src IP", "Dst IP", "Severity"]]
        for ev in timeline[:15]:
            tl_data.append([
                str(ev.get("timestamp", ""))[:19],
                str(ev.get("action", ""))[:40],
                str(ev.get("src_ip", "N/A") or "N/A"),
                str(ev.get("dst_ip", "N/A") or "N/A"),
                str(ev.get("severity_label", "info")),
            ])
        tt = Table(tl_data, colWidths=[38*mm, 60*mm, 28*mm, 28*mm, 18*mm])
        tt.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), brand_dark),
            ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 7),
            ("GRID",        (0,0), (-1,-1), 0.3, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F5F5")]),
            ("TOPPADDING",  (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        elements += [tt, Spacer(1, 4*mm)]
    else:
        elements.append(Paragraph("No timeline events captured.", body))
        elements.append(Spacer(1, 4*mm))

    # ── Recommended Playbook ──────────────────────────────────────────────────
    if playbook:
        elements.append(Paragraph("4. Response Playbook", h2))
        elements.append(Paragraph(f"<b>{playbook.code}</b> — {playbook.name}", bold))
        elements.append(Paragraph(playbook.description, body))
        elements.append(Spacer(1, 2*mm))
        for i, action in enumerate(playbook.actions, 1):
            elements.append(Paragraph(f"&nbsp;&nbsp;{i}. {action}", body))
        elements.append(Spacer(1, 4*mm))

    # ── Response Outcome ──────────────────────────────────────────────────────
    if response_logs:
        rl = response_logs[-1]
        elements.append(Paragraph("5. Response Outcome", h2))
        outcome = rl.outcome or {}
        elements.append(Paragraph(outcome.get("result", "Response executed."), body))
        elements.append(Spacer(1, 4*mm))

    # ── Compliance Impact ─────────────────────────────────────────────────────
    elements.append(Paragraph("6. Compliance Framework Impact", h2))
    compliance = _get_compliance(alert.domain)
    comp_data  = [["Framework", "Applicable Controls"]]
    for fw, controls in compliance.items():
        comp_data.append([fw, "\n".join(controls)])
    ct = Table(comp_data, colWidths=[30*mm, 145*mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1A2B4A")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    elements += [ct, Spacer(1, 4*mm)]

    # ── Audit Trail ───────────────────────────────────────────────────────────
    elements.append(Paragraph("7. Agent Audit Trail", h2))
    at_data = [["Timestamp", "Agent", "Action", "Confidence"]]
    for ae in audit_entries:
        at_data.append([
            ae.timestamp.strftime("%H:%M:%S"),
            ae.agent_name,
            ae.action[:60],
            f"{int((ae.confidence or 0)*100)}%" if ae.confidence else "N/A",
        ])
    att = Table(at_data, colWidths=[22*mm, 38*mm, 100*mm, 18*mm])
    att.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1A2B4A")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 7),
        ("GRID",        (0,0), (-1,-1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F5F5")]),
        ("TOPPADDING",  (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0),(-1,-1), 3),
    ]))
    elements += [att, Spacer(1, 4*mm)]

    # ── Footer ────────────────────────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    elements.append(Paragraph(
        f"Generated by SENTINEL-AI Autonomous SOC Platform &nbsp;|&nbsp; "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; "
        f"CONFIDENTIAL — For authorized personnel only",
        sub
    ))

    doc.build(elements)
    return output_path


async def run_auditor(db: AsyncSession, incident_id: str, org_id: str, org_name: str):
    """Generate PDF report and create audit entry."""
    await manager.broadcast("pipeline_progress", {
        "incident_id": incident_id,
        "stage": "AUDITING",
        "message": "Sentinel-Auditor: Generating investigation report...",
    })

    # Load all required data
    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident   = inc_result.scalar_one_or_none()
    if not incident:
        return None

    alert_result = await db.execute(select(Alert).where(Alert.id == incident.alert_id))
    alert        = alert_result.scalar_one_or_none()

    audit_result = await db.execute(select(AuditEntry).where(AuditEntry.incident_id == incident_id))
    audit_entries = audit_result.scalars().all()

    rl_result    = await db.execute(select(ResponseLog).where(ResponseLog.incident_id == incident_id))
    response_logs = rl_result.scalars().all()

    playbook = None
    if incident.recommended_playbook_id:
        pb_result = await db.execute(select(Playbook).where(Playbook.id == incident.recommended_playbook_id))
        playbook  = pb_result.scalar_one_or_none()

    # Generate PDF
    filename    = f"SENTINEL_REPORT_{incident_id[:8].upper()}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(settings.REPORTS_DIR, filename)

    try:
        generate_pdf(incident, alert, audit_entries, response_logs, playbook, org_name, output_path)
    except Exception as exc:
        await manager.broadcast("pipeline_progress", {
            "incident_id": incident_id, "stage": "AUDIT_ERROR",
            "message": f"Report generation failed: {exc}",
        })
        raise

    # Save Report record
    report = Report(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        org_id=org_id,
        filename=filename,
        file_path=output_path,
        compliance_mapping=_get_compliance(alert.domain if alert else "network_security"),
    )
    db.add(report)

    # Final audit entry
    final_audit = AuditEntry(
        incident_id=incident_id,
        agent_name="Sentinel-Auditor",
        action="Investigation report generated and audit trail sealed",
        details={"filename": filename, "compliance_frameworks": ["GDPR", "HIPAA", "SOC2", "ISO27001"]},
        confidence=1.0,
    )
    db.add(final_audit)
    await db.commit()

    await manager.broadcast("pipeline_progress", {
        "incident_id": incident_id,
        "stage": "COMPLETE",
        "message": f"Sentinel-Auditor: Report ready — {filename}",
        "report_filename": filename,
        "report_id": report.id,
    })

    return report


def _get_compliance(domain: str) -> dict:
    return COMPLIANCE_MAP.get(domain, {
        "GDPR": ["Art. 32 — Security of Processing"],
        "HIPAA": ["164.308(a)(1) — Risk Analysis"],
        "SOC2": ["CC7.1 — Threat Detection"],
        "ISO27001": ["A.16 — Incident Management"],
    })
