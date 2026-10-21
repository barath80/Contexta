"""
Contexta Backend - CVE routes
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.cve import CVEListResponse, CVEResponse
from app.services.cve_service import CVEService

router = APIRouter()


@router.get("/stats", response_model=Dict[str, Any])
async def stats(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await CVEService(db).statistics()


@router.get("/trending", response_model=List[CVEResponse])
async def trending(limit: int = Query(10, ge=1, le=50), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = CVEService(db)
    return await svc.serialize(await svc.trending(limit))


@router.get("", response_model=CVEListResponse)
async def list_cves(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    min_cvss: Optional[float] = Query(None, ge=0, le=10), has_exploit: Optional[bool] = None, kev: Optional[bool] = None,
    q: Optional[str] = Query(None, max_length=100), sort: str = Query("recent", pattern="^(recent|cvss|epss)$"),
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = CVEService(db)
    rows, total = await svc.list(page, page_size, severity, min_cvss, has_exploit, kev, q, sort)
    return {"items": await svc.serialize(rows), "total": total, "page": page, "page_size": page_size}


@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(cve_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = CVEService(db)
    cve = await svc.get_by_cve_id(cve_id)
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE not found")
    return (await svc.serialize([cve]))[0]
