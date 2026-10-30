"""
SENTINEL-AI — Reports Router
  GET  /api/v1/reports/              — list all reports
  GET  /api/v1/reports/{id}          — report metadata
  GET  /api/v1/reports/{id}/download — stream PDF file
"""
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.models import Report

router = APIRouter()


@router.get("/", summary="List all investigation reports")
async def list_reports(org_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Report).order_by(desc(Report.created_at))
    if org_id:
        q = q.where(Report.org_id == org_id)
    result = await db.execute(q)
    reports = result.scalars().all()
    return [
        {
            "id": r.id,
            "incident_id": r.incident_id,
            "org_id": r.org_id,
            "filename": r.filename,
            "compliance_mapping": r.compliance_mapping,
            "created_at": r.created_at.isoformat(),
        }
        for r in reports
    ]


@router.get("/{report_id}", summary="Get report metadata")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": r.id, "incident_id": r.incident_id, "org_id": r.org_id,
        "filename": r.filename, "file_path": r.file_path,
        "compliance_mapping": r.compliance_mapping,
        "created_at": r.created_at.isoformat(),
    }


@router.get("/{report_id}/download", summary="Download PDF report")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    if not os.path.exists(r.file_path):
        raise HTTPException(status_code=404, detail="PDF file not found on disk")
    return FileResponse(
        path=r.file_path,
        media_type="application/pdf",
        filename=r.filename,
    )
