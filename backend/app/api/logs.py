"""
SENTINEL-AI — Logs Router
  POST /api/v1/logs/upload            — upload raw log file
  GET  /api/v1/logs/                  — list logs
  GET  /api/v1/logs/{log_id}          — get single log
  POST /api/v1/logs/synthetic/{domain} — generate + run synthetic demo
"""
import hashlib
import os
import uuid
import asyncio
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.core.config import settings
from app.models.models import SecurityLog, Organization
from app.agents.orchestrator import run_pipeline

router = APIRouter()

ALLOWED_EXTENSIONS = {".csv", ".json", ".log", ".txt"}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _log_to_dict(log: SecurityLog) -> dict:
    return {
        "id": log.id,
        "org_id": log.org_id,
        "original_filename": log.original_filename,
        "sha256_hash": log.sha256_hash,
        "domain": log.domain,
        "status": log.status,
        "record_count": log.record_count,
        "attack_count": log.attack_count,
        "error_message": log.error_message,
        "created_at": log.created_at.isoformat(),
    }


@router.post("/upload", summary="Upload a raw security log file")
async def upload_log(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    org_id: str = Form(...),
    domain: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    # Validate org
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Validate extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File type '{ext}' not allowed. Use: {ALLOWED_EXTENSIONS}")

    # Save file
    stored_name = f"{uuid.uuid4()}{ext}"
    upload_path = os.path.join(settings.UPLOAD_DIR, stored_name)
    content = await file.read()
    with open(upload_path, "wb") as f:
        f.write(content)

    # SHA-256
    sha = _sha256(upload_path)

    # Create DB record
    log_record = SecurityLog(
        id=str(uuid.uuid4()),
        org_id=org_id,
        original_filename=file.filename,
        stored_filename=stored_name,
        sha256_hash=sha,
        domain=domain,
        status="UPLOADED",
    )
    db.add(log_record)
    await db.commit()
    await db.refresh(log_record)

    # Kick off pipeline in background
    background_tasks.add_task(run_pipeline, log_record.id, upload_path, org_id, domain)

    return {"log_id": log_record.id, "sha256": sha, "status": "PIPELINE_STARTED"}


@router.post("/synthetic/{domain}", summary="Generate synthetic logs and run pipeline demo")
async def run_synthetic_demo(
    domain: str,
    background_tasks: BackgroundTasks,
    org_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Generate a synthetic CSV for the specified domain and run the full pipeline."""
    import pandas as pd, sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "scripts" / "dataset_preparation"))

    # Pick first org if none given
    if not org_id:
        orgs_result = await db.execute(select(Organization).limit(1))
        org = orgs_result.scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=400, detail="No organizations found. Seed first.")
        org_id = org.id

    # Use existing normalized CSV for this domain
    norm_dir = Path(settings.NORMALIZED_DATA_DIR)
    # Map domain key to file
    domain_file_map = {
        "network_security":    "network_security_synthetic_ces.csv",
        "endpoint_security":   "endpoint_security_synthetic_ces.csv",
        "cloud_infrastructure":"cloud_infrastructure_synthetic_ces.csv",
        "iam":                 "iam_synthetic_ces.csv",
        "application_security":"application_security_synthetic_ces.csv",
        "dlp":                 "dlp_synthetic_ces.csv",
        "insider_threat":      "insider_threat_synthetic_ces.csv",
        "compliance":          "compliance_synthetic_ces.csv",
    }
    filename = domain_file_map.get(domain)
    if not filename:
        raise HTTPException(status_code=400, detail=f"Unknown domain: {domain}")

    src_path = norm_dir / filename
    if not src_path.exists():
        raise HTTPException(status_code=404, detail=f"Synthetic dataset not found: {src_path}")

    # Sample 500 rows (fast demo)
    df = pd.read_csv(src_path).head(500)
    stored_name = f"{uuid.uuid4()}.csv"
    dest_path = os.path.join(settings.UPLOAD_DIR, stored_name)
    df.to_csv(dest_path, index=False)

    sha = _sha256(dest_path)

    log_record = SecurityLog(
        id=str(uuid.uuid4()),
        org_id=org_id,
        original_filename=f"SYNTHETIC_{domain}_demo.csv",
        stored_filename=stored_name,
        sha256_hash=sha,
        domain=domain,
        status="UPLOADED",
    )
    db.add(log_record)
    await db.commit()
    await db.refresh(log_record)

    background_tasks.add_task(run_pipeline, log_record.id, dest_path, org_id, domain)

    return {"log_id": log_record.id, "sha256": sha, "domain": domain, "rows": len(df), "status": "PIPELINE_STARTED"}


@router.get("/", summary="List all security logs")
async def list_logs(org_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(SecurityLog).order_by(desc(SecurityLog.created_at))
    if org_id:
        q = q.where(SecurityLog.org_id == org_id)
    result = await db.execute(q)
    return [_log_to_dict(l) for l in result.scalars().all()]


@router.get("/{log_id}", summary="Get a specific log record")
async def get_log(log_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SecurityLog).where(SecurityLog.id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return _log_to_dict(log)
