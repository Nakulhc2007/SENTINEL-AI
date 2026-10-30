"""
SENTINEL-AI — Organizations Router
"""
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Organization

router = APIRouter()

# 8 demo organizations — one per security domain
DEMO_ORGS = [
    {"name": "AcmeCorp",         "industry": "Finance",       "domain": "network_security",    "risk_threshold": 70, "compliance_frameworks": ["GDPR", "SOC2", "ISO27001"],       "description": "Global financial services corporation."},
    {"name": "HealthFirst",      "industry": "Healthcare",    "domain": "endpoint_security",   "risk_threshold": 60, "compliance_frameworks": ["HIPAA", "SOC2"],                  "description": "National healthcare provider network."},
    {"name": "CloudNative Inc.", "industry": "Technology",    "domain": "cloud_infrastructure","risk_threshold": 75, "compliance_frameworks": ["SOC2", "ISO27001"],               "description": "Cloud-native SaaS platform provider."},
    {"name": "SecureBank",       "industry": "Banking",       "domain": "iam",                 "risk_threshold": 65, "compliance_frameworks": ["PCI-DSS", "SOC2", "GDPR"],        "description": "Digital-first banking institution."},
    {"name": "ShopStream",       "industry": "E-Commerce",    "domain": "application_security","risk_threshold": 72, "compliance_frameworks": ["PCI-DSS", "GDPR"],                "description": "High-volume online retail platform."},
    {"name": "DataVault Corp",   "industry": "Data Services", "domain": "dlp",                 "risk_threshold": 68, "compliance_frameworks": ["GDPR", "CCPA", "ISO27001"],       "description": "Enterprise data warehouse and analytics."},
    {"name": "GovSecure",        "industry": "Government",    "domain": "insider_threat",      "risk_threshold": 55, "compliance_frameworks": ["NIST", "FISMA", "ISO27001"],      "description": "Federal government agency IT division."},
    {"name": "AuditMind",        "industry": "Consulting",    "domain": "compliance",          "risk_threshold": 80, "compliance_frameworks": ["GDPR", "SOC2", "HIPAA", "ISO27001"], "description": "Enterprise risk and compliance consultancy."},
]


async def seed_organizations(db: AsyncSession):
    """Seed 8 default organizations if they don't exist."""
    result = await db.execute(select(Organization).limit(1))
    existing = result.scalar_one_or_none()
    if existing:
        return

    for org_data in DEMO_ORGS:
        org = Organization(
            id=str(uuid.uuid4()),
            name=org_data["name"],
            industry=org_data["industry"],
            domain=org_data["domain"],
            risk_threshold=org_data["risk_threshold"],
            compliance_frameworks=org_data["compliance_frameworks"],
            description=org_data["description"],
        )
        db.add(org)
    await db.commit()


@router.get("/", summary="List all organizations")
async def list_orgs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Organization).order_by(Organization.name))
    orgs = result.scalars().all()
    return [
        {
            "id": o.id,
            "name": o.name,
            "industry": o.industry,
            "domain": o.domain,
            "risk_threshold": o.risk_threshold,
            "compliance_frameworks": o.compliance_frameworks,
            "description": o.description,
            "created_at": o.created_at.isoformat(),
        }
        for o in orgs
    ]


@router.get("/{org_id}", summary="Get organization by ID")
async def get_org(org_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return {
        "id": org.id,
        "name": org.name,
        "industry": org.industry,
        "domain": org.domain,
        "risk_threshold": org.risk_threshold,
        "compliance_frameworks": org.compliance_frameworks,
        "description": org.description,
        "created_at": org.created_at.isoformat(),
    }
