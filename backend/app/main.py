"""
SENTINEL-AI — FastAPI Main Entry Point
=======================================
Mounts all routers, initialises the DB, seeds data, and runs the WebSocket server.
"""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.core.database import init_db
from app.core.config import settings
from app.core.websocket_manager import manager
from app.api import logs, alerts, incidents, playbooks, reports, orgs, audit


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks: init DB, seed orgs + playbooks."""
    await init_db()

    # Seed orgs and playbooks inside an async session
    from app.core.database import AsyncSessionLocal
    from app.agents.remediator import seed_playbooks
    from app.api.orgs import seed_organizations

    async with AsyncSessionLocal() as db:
        await seed_organizations(db)
        await seed_playbooks(db)

    yield
    # Shutdown — nothing needed


app = FastAPI(
    title="SENTINEL-AI",
    description="Autonomous AI-Powered Security Operations Center",
    version=settings.VERSION,
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ───────────────────────────────────────────────────────────────
app.include_router(orgs.router,       prefix="/api/v1/orgs",       tags=["Organizations"])
app.include_router(logs.router,       prefix="/api/v1/logs",       tags=["Logs"])
app.include_router(alerts.router,     prefix="/api/v1/alerts",     tags=["Alerts"])
app.include_router(incidents.router,  prefix="/api/v1/incidents",  tags=["Incidents"])
app.include_router(playbooks.router,  prefix="/api/v1/playbooks",  tags=["Playbooks"])
app.include_router(reports.router,    prefix="/api/v1/reports",    tags=["Reports"])
app.include_router(audit.router,      prefix="/api/v1/audit",      tags=["Audit"])


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive by waiting for client ping
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "SENTINEL-AI", "version": settings.VERSION}


@app.get("/", tags=["Root"])
async def root():
    return {"message": "SENTINEL-AI API — visit /docs for Swagger UI"}
