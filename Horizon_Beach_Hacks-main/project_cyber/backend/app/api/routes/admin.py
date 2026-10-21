"""
Contexta Backend - Settings, system status, admin operations and blocklist
"""

import hmac
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gemini import get_ai
from app.auth.jwt import (
    decode_token, get_current_user, load_user_for_token, oauth2_scheme_optional, require_admin, require_analyst,
)
from app.config import settings
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.extras import BlockedIndicator
from app.models.risk import Risk
from app.models.user import User
from app.services import ledger_service, settings_service
from app.services.asset_service import AssetService
from app.utils.net import assert_public_http_url
from app.workers import scheduler

router = APIRouter()
blocklist_router = APIRouter()


class OrganizationSettings(BaseModel):
    name: str = Field(default="", max_length=200)
    industry: str = Field(default="technology", max_length=100)
    region: str = Field(default="global", max_length=100)
    size: str = Field(default="medium", pattern="^(small|medium|large|enterprise)$")
    compliance_frameworks: List[str] = Field(default_factory=list, max_length=20)


class IntegrationSettings(BaseModel):
    notification_webhook_url: str = Field(default="", max_length=500, pattern=r"^(https?://.*)?$")
    containment_webhook_url: str = Field(default="", max_length=500, pattern=r"^(https?://.*)?$")


def _mask(url: str) -> str:
    return "" if not url else url[:24] + "..." + url[-4:] if len(url) > 32 else url


# ----------------------------------------------------------------- settings
@router.get("/organization", response_model=Dict[str, Any])
async def get_organization(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await settings_service.get_setting(db, "organization")


@router.put("/organization", response_model=Dict[str, Any])
async def put_organization(data: OrganizationSettings, user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    res = await settings_service.set_setting(db, "organization", data.model_dump(), user.email)
    await ledger_service.record(LedgerEventTypes.SYSTEM_CONFIG_CHANGED, actor=user.email, data={"section": "organization"})
    return res


@router.get("/integrations", response_model=Dict[str, Any])
async def get_integrations(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    cfg = await settings_service.get_setting(db, "integrations")
    return {k: {"configured": bool(v), "preview": _mask(v)} for k, v in cfg.items()}


@router.put("/integrations", response_model=Dict[str, Any])
async def put_integrations(data: IntegrationSettings, user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    for url in (data.notification_webhook_url, data.containment_webhook_url):
        if url:
            try:
                await assert_public_http_url(url)
            except ValueError as exc:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    await settings_service.set_setting(db, "integrations", data.model_dump(), user.email)
    await ledger_service.record(LedgerEventTypes.SYSTEM_CONFIG_CHANGED, actor=user.email, data={"section": "integrations"})
    cfg = await settings_service.get_setting(db, "integrations")
    return {k: {"configured": bool(v), "preview": _mask(v)} for k, v in cfg.items()}


# ------------------------------------------------------------------- system
@router.get("/system", response_model=Dict[str, Any])
async def system_status(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as exc:  # pragma: no cover
        db_status = f"unhealthy: {exc}"
    ai = get_ai()
    ledger = await ledger_service.verify_chain(db)
    return {
        "environment": settings.app_env,
        "database": {"status": db_status, "engine": "sqlite" if settings.is_sqlite else "postgresql"},
        "ai": {"configured": bool(getattr(ai, "configured", False)), "provider": getattr(ai, "label", None),
               "mode": "ai" if getattr(ai, "configured", False) else "rules"},
        "feeds": {"nvd_api_key": bool(settings.nvd_api_key), "cisa_kev_url": settings.cisa_kev_url},
        "siem": {"ingest_api_key_set": bool(settings.ingest_api_key)},
        "registration_enabled": settings.allow_registration,
        "counts": {
            "assets": await AssetService(db).count(),
            "cves": (await db.execute(select(func.count(CVE.id)))).scalar() or 0,
            "risks": (await db.execute(select(func.count(Risk.id)))).scalar() or 0,
            "users": (await db.execute(select(func.count(User.id)))).scalar() or 0,
        },
        "ledger": {"valid": ledger["valid"], "blocks": ledger["blocks_verified"], "issues": ledger["issues"][:5]},
        "jobs": await scheduler.job_status(),
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/jobs/{job_id}/run", response_model=Dict[str, Any], status_code=status.HTTP_202_ACCEPTED)
async def run_job(job_id: str, user: User = Depends(require_admin)):
    if job_id not in scheduler.JOBS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown job. Valid: {list(scheduler.JOBS)}")
    scheduler.launch_background(job_id)
    await ledger_service.record(LedgerEventTypes.ACTION_TAKEN, actor=user.email, data={"action": "run_job", "job": job_id})
    return {"job": job_id, "status": "started"}


# ---------------------------------------------------------------- blocklist
async def _blocklist_principal(
    x_api_key: Optional[str] = Header(default=None),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    db: AsyncSession = Depends(get_db),
) -> str:
    if x_api_key and settings.ingest_api_key and hmac.compare_digest(x_api_key, settings.ingest_api_key):
        return "api-key"
    if token:
        return (await load_user_for_token(db, decode_token(token, "access"))).email
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Provide X-API-Key or a Bearer token")


async def _active_indicators(db: AsyncSession) -> List[BlockedIndicator]:
    now = datetime.utcnow()
    rows = await db.execute(
        select(BlockedIndicator).where(or_(BlockedIndicator.expires_at == None, BlockedIndicator.expires_at > now))  # noqa: E711
        .order_by(BlockedIndicator.created_at.desc())
    )
    return list(rows.scalars().all())


@blocklist_router.get("/blocklist", response_model=List[Dict[str, Any]])
async def blocklist(_: str = Depends(_blocklist_principal), db: AsyncSession = Depends(get_db)):
    return [{"id": str(b.id), "type": b.indicator_type, "value": b.value, "reason": b.reason, "created_by": b.created_by,
             "created_at": b.created_at, "incident_id": str(b.incident_id) if b.incident_id else None}
            for b in await _active_indicators(db)]


@blocklist_router.get("/blocklist.txt")
async def blocklist_txt(kind: str = Query("ip", pattern="^(ip|domain|hash)$"), _: str = Depends(_blocklist_principal),
                        db: AsyncSession = Depends(get_db)):
    """Plain-text feed (one indicator per line) for firewalls, proxies and EDR."""
    values = [b.value for b in await _active_indicators(db) if b.indicator_type == kind]
    return Response("\n".join(values) + ("\n" if values else ""), media_type="text/plain")


@blocklist_router.delete("/blocklist/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unblock(indicator_id: str, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(indicator_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found")
    row = (await db.execute(select(BlockedIndicator).where(BlockedIndicator.id == uid))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found")
    await ledger_service.record(LedgerEventTypes.ACTION_TAKEN, actor=user.email,
                                data={"action": "unblock_indicator", "type": row.indicator_type, "value": row.value})
    await db.delete(row)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
