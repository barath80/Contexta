"""
Contexta Backend - Alerts (security events) and SIEM ingestion routes
"""

import hmac
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, oauth2_scheme_optional, require_analyst, decode_token, load_user_for_token
from app.config import settings
from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.log import AlertListResponse, AlertResponse, IngestRequest, IngestResult
from app.services.log_service import LogService

router = APIRouter()


def _parse_since(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid 'since' timestamp (use ISO 8601)")


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    min_severity: Optional[str] = Query(None, pattern="^(info|low|medium|high|critical)$"),
    status_filter: Optional[str] = Query(None, alias="status", pattern="^(new|acknowledged|dismissed)$"),
    category: Optional[str] = None, asset_id: Optional[UUID] = None, q: Optional[str] = Query(None, max_length=100),
    since: Optional[str] = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = LogService(db)
    try:
        items, total = await svc.list_alerts(page, page_size, min_severity, status_filter, category, asset_id, q, _parse_since(since))
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown category")
    seen = _parse_since((user.preferences or {}).get("alerts_seen_at"))
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "unread": await svc.unread_count(seen, (user.preferences or {}).get("alert_min_severity", "high"))}


@router.get("/stats", response_model=Dict[str, Any])
async def stats(hours: int = Query(24, ge=1, le=720), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await LogService(db).statistics(hours)


@router.get("/unread", response_model=Dict[str, int])
async def unread(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    prefs = user.preferences or {}
    return {"unread": await LogService(db).unread_count(_parse_since(prefs.get("alerts_seen_at")), prefs.get("alert_min_severity", "high"))}


@router.post("/mark-seen", response_model=Dict[str, str])
async def mark_seen(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow().isoformat()
    user.preferences = {**(user.preferences or {}), "alerts_seen_at": now}
    await db.flush()
    return {"alerts_seen_at": now}


async def _set_status(log_id: UUID, new_status: str, user: User, db: AsyncSession) -> Dict[str, Any]:
    from sqlalchemy import select

    from app.models.asset import Asset

    svc = LogService(db)
    log = await svc.get(log_id)
    if log is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    await svc.set_status(log, new_status, user.id)
    name = (await db.execute(select(Asset.name).where(Asset.id == log.asset_id))).scalar_one_or_none() if log.asset_id else None
    return svc.serialize(log, name)


@router.post("/{log_id}/acknowledge", response_model=AlertResponse)
async def acknowledge(log_id: UUID, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    return await _set_status(log_id, "acknowledged", user, db)


@router.post("/{log_id}/dismiss", response_model=AlertResponse)
async def dismiss(log_id: UUID, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    return await _set_status(log_id, "dismissed", user, db)


# ------------------------------------------------------------------ ingestion
ingest_router = APIRouter()


async def _ingest_principal(
    x_api_key: Optional[str] = Header(default=None),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    db: AsyncSession = Depends(get_db),
) -> str:
    """Machine sources send X-API-Key; people send a Bearer token (analyst or admin)."""
    if x_api_key and settings.ingest_api_key and hmac.compare_digest(x_api_key, settings.ingest_api_key):
        return "api-key"
    if token:
        user = await load_user_for_token(db, decode_token(token, "access"))
        if user.role in (UserRole.ADMIN, UserRole.ANALYST):
            return user.email
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Provide X-API-Key or a Bearer token")


@ingest_router.post("/ingest", response_model=IngestResult, status_code=status.HTTP_202_ACCEPTED)
async def ingest(body: IngestRequest, principal: str = Depends(_ingest_principal), db: AsyncSession = Depends(get_db)):
    """Push security events from a SIEM / log shipper. Events are resolved to assets and correlated into risks."""
    from app.services import ledger_service

    result = await LogService(db).ingest([e.model_dump() for e in body.events], simulated=False)
    await ledger_service.record("events_ingested", actor=principal, data={"count": result["ingested"], "risks_created": result["risks_created"]})
    return result
