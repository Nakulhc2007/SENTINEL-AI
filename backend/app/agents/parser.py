"""
SENTINEL-AI — Sentinel-Parser Agent (Agent 1)
=============================================
Ingests uploaded CSV/JSON/plaintext security log files,
normalizes records into the Common Event Schema (CES),
computes SHA-256 of the file, and saves events to the database.
"""
import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update

from app.models.models import SecurityLog, NormalizedEvent, AuditEntry
from app.core.config import settings
from app.core.websocket_manager import manager

SEVERITY_LABEL_TO_INT = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}

# CES columns we expect in synthetic normalized CSVs
CES_COLUMNS_MAP = {
    "event_id": "event_id",
    "timestamp": "timestamp",
    "domain": "domain",
    "organization_id": "org_id_source",
    "event_type": "event_type",
    "severity": "severity",
    "severity_label": "severity_label",
    "action": "action",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "username": "username",
    "hostname": "hostname",
    "process_name": "process_name",
    "file_path": "file_path",
    "is_attack": "is_attack",
    "attack_type": "attack_type",
    "raw_log": "raw_log",
    "sha256": "sha256",
    "extra_fields": "extra_fields",
}


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_extra_fields(val) -> dict:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return {}
    if isinstance(val, dict):
        return val
    try:
        return json.loads(str(val))
    except Exception:
        return {}


def parse_bool(val) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    return s in ("true", "1", "yes")


def severity_to_int(val) -> int:
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        return min(4, max(0, int(val)))
    return SEVERITY_LABEL_TO_INT.get(str(val).lower(), 0)


async def run_parser(db: AsyncSession, log_id: str, file_path: str, org_id: str, domain: str):
    """Main parser entry point. Called by orchestrator as a background task."""
    # Update status → PARSING
    await db.execute(
        update(SecurityLog)
        .where(SecurityLog.id == log_id)
        .values(status="PARSING")
    )
    await db.commit()

    await manager.broadcast("pipeline_progress", {
        "log_id": log_id,
        "stage": "PARSING",
        "message": "Sentinel-Parser: Reading and normalizing log file...",
    })

    try:
        # ── Step 1: Compute file SHA-256 ─────────────────────────────────
        file_sha256 = compute_file_sha256(file_path)

        # ── Step 2: Detect and read file format ──────────────────────────
        ext = Path(file_path).suffix.lower()
        if ext == ".csv":
            df = pd.read_csv(file_path, low_memory=False)
        elif ext in (".json", ".jsonl"):
            try:
                df = pd.read_json(file_path)
            except ValueError:
                df = pd.read_json(file_path, lines=True)
        else:
            # Plaintext: each line is a raw log
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
            df = pd.DataFrame({"raw_log": [l.strip() for l in lines if l.strip()]})

        # ── Step 3: Map columns to CES names ─────────────────────────────
        # If file has CES columns, use them directly; otherwise, do best-effort mapping
        available = set(df.columns.str.lower())
        is_ces = "severity_label" in available or "is_attack" in available

        events = []
        for idx, row in df.iterrows():
            if is_ces:
                sev_raw = row.get("severity", row.get("severity_label", 0))
                sev_int = severity_to_int(sev_raw)
                sev_label = row.get("severity_label") or ["info","low","medium","high","critical"][sev_int]

                event = NormalizedEvent(
                    id=str(uuid.uuid4()),
                    log_id=log_id,
                    org_id=org_id,
                    domain=domain,
                    timestamp=str(row.get("timestamp", datetime.utcnow().isoformat())),
                    src_ip=row.get("src_ip") if pd.notna(row.get("src_ip", None)) else None,
                    dst_ip=row.get("dst_ip") if pd.notna(row.get("dst_ip", None)) else None,
                    src_port=int(row["src_port"]) if pd.notna(row.get("src_port")) else None,
                    dst_port=int(row["dst_port"]) if pd.notna(row.get("dst_port")) else None,
                    protocol=row.get("protocol") if pd.notna(row.get("protocol", None)) else None,
                    action=str(row.get("action", "unknown")),
                    severity=sev_int,
                    severity_label=sev_label,
                    username=row.get("username") if pd.notna(row.get("username", None)) else None,
                    hostname=row.get("hostname") if pd.notna(row.get("hostname", None)) else None,
                    process_name=row.get("process_name") if pd.notna(row.get("process_name", None)) else None,
                    file_path=row.get("file_path") if pd.notna(row.get("file_path", None)) else None,
                    is_attack=parse_bool(row.get("is_attack")),
                    attack_type=row.get("attack_type") if pd.notna(row.get("attack_type", None)) else None,
                    raw_log=str(row.get("raw_log", str(row.to_dict())))[:2000],
                    sha256=row.get("sha256") if pd.notna(row.get("sha256", None)) else None,
                    extra_fields=parse_extra_fields(row.get("extra_fields")),
                )
            else:
                # Generic plaintext / unknown format
                event = NormalizedEvent(
                    id=str(uuid.uuid4()),
                    log_id=log_id,
                    org_id=org_id,
                    domain=domain,
                    timestamp=datetime.utcnow().isoformat(),
                    action="log_entry",
                    severity=0,
                    severity_label="info",
                    raw_log=str(row.get("raw_log", str(row.to_dict())))[:2000],
                )
            events.append(event)

        # ── Step 4: Batch-insert events ───────────────────────────────────
        BATCH = 500
        for i in range(0, len(events), BATCH):
            db.add_all(events[i: i + BATCH])
            await db.commit()

        attack_count = sum(1 for e in events if e.is_attack is True)

        # ── Step 5: Update SecurityLog ────────────────────────────────────
        await db.execute(
            update(SecurityLog)
            .where(SecurityLog.id == log_id)
            .values(
                status="PARSED",
                sha256_hash=file_sha256,
                record_count=len(events),
                attack_count=attack_count,
            )
        )
        await db.commit()

        # ── Step 6: Audit entry ───────────────────────────────────────────
        audit = AuditEntry(
            log_id=log_id,
            agent_name="Sentinel-Parser",
            action="Log file parsed and normalized",
            details={
                "total_records": len(events),
                "attack_records": attack_count,
                "sha256": file_sha256,
                "domain": domain,
            },
            confidence=1.0,
        )
        db.add(audit)
        await db.commit()

        await manager.broadcast("pipeline_progress", {
            "log_id": log_id,
            "stage": "PARSED",
            "message": f"Sentinel-Parser: Normalized {len(events):,} events ({attack_count} attacks detected in labels).",
            "records": len(events),
            "attacks": attack_count,
        })

        return {"log_id": log_id, "records": len(events), "sha256": file_sha256, "attack_count": attack_count}

    except Exception as exc:
        await db.execute(
            update(SecurityLog)
            .where(SecurityLog.id == log_id)
            .values(status="ERROR", error_message=str(exc))
        )
        await db.commit()
        await manager.broadcast("pipeline_progress", {
            "log_id": log_id,
            "stage": "ERROR",
            "message": f"Sentinel-Parser ERROR: {exc}",
        })
        raise
