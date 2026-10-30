"""
SENTINEL-AI — Pipeline Orchestrator
=====================================
Coordinates the 5-agent pipeline:
Parser → Analyst → Investigator → [AWAIT_APPROVAL] → Remediator → Auditor

Uses FastAPI BackgroundTasks for async execution and streams status
updates to all connected WebSocket clients.
"""
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.parser import run_parser
from app.agents.analyst import run_analyst
from app.agents.investigator import run_investigator
from app.core.websocket_manager import manager
from app.core.database import AsyncSessionLocal


async def run_pipeline(log_id: str, file_path: str, org_id: str, domain: str):
    """
    Full pipeline: Parser → Analyst → Investigator.
    Runs in a background task with its own DB session.
    Remediator is triggered separately by human approval.
    """
    async with AsyncSessionLocal() as db:
        try:
            # ── Stage 1: Sentinel-Parser ──────────────────────────────────
            parser_result = await run_parser(db, log_id, file_path, org_id, domain)

            # ── Stage 2: Sentinel-Analyst ─────────────────────────────────
            alerts        = await run_analyst(db, log_id, org_id)
            alert_ids     = [a.id for a in alerts]

            if not alert_ids:
                await manager.broadcast("pipeline_progress", {
                    "log_id": log_id,
                    "stage": "COMPLETE",
                    "message": "Pipeline complete. No threats detected in this log file.",
                    "threat_count": 0,
                })
                return

            # ── Stage 3: Sentinel-Investigator ────────────────────────────
            incidents     = await run_investigator(db, log_id, org_id, alert_ids)

            await manager.broadcast("pipeline_progress", {
                "log_id": log_id,
                "stage": "AWAITING_APPROVAL",
                "message": (
                    f"Pipeline paused — {len(incidents)} incident(s) require human approval "
                    f"in the Response Center before remediation begins."
                ),
                "incidents": len(incidents),
                "alert_ids": alert_ids,
            })

        except Exception as exc:
            await manager.broadcast("pipeline_progress", {
                "log_id": log_id,
                "stage": "PIPELINE_ERROR",
                "message": f"Pipeline error: {str(exc)}",
            })
            raise
