"""
Contexta Backend - Dashboard, reports and search routes
"""

from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_analyst
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.user import User
from app.services import dashboard_service, ledger_service, report_service, search_service

router = APIRouter()
reports_router = APIRouter()
search_router = APIRouter()


@router.get("/overview", response_model=Dict[str, Any])
async def overview(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.overview(db)


@router.get("/trend", response_model=Dict[str, Any])
async def trend(days: int = Query(30, ge=1, le=365), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.risk_trend(db, days)


@router.get("/departments", response_model=List[Dict[str, Any]])
async def departments(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.departments(db)


@router.get("/vulnerabilities", response_model=List[Dict[str, Any]])
async def vulnerabilities(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.vulnerability_distribution(db)


@router.get("/actions", response_model=List[Dict[str, Any]])
async def actions(limit: int = Query(6, ge=1, le=20), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.recommended_actions(db, limit)


@router.get("/executive", response_model=Dict[str, Any])
async def executive(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.executive(db)


# --------------------------------------------------------------------- reports
@reports_router.get("/analytics", response_model=Dict[str, Any])
async def analytics(months: int = Query(6, ge=1, le=24), weeks: int = Query(6, ge=1, le=26),
                    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await dashboard_service.reports(db, months, weeks)


@reports_router.post("/board", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def generate_board_report(user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    report = await report_service.generate_board_report(db, user.id, user.email)
    await ledger_service.record(LedgerEventTypes.REPORT_GENERATED, actor=user.email, resource_type="report",
                                resource_id=str(report.id), data={"kind": "board", "generated_by": report.generated_by})
    return {"id": report.id, "kind": report.kind, "title": report.title, "content": report.content,
            "generated_by": report.generated_by, "created_at": report.created_at}


@reports_router.get("", response_model=List[Dict[str, Any]])
async def list_reports(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return [{"id": r.id, "kind": r.kind, "title": r.title, "generated_by": r.generated_by, "created_at": r.created_at}
            for r in await report_service.list_reports(db)]


@reports_router.get("/{report_id}", response_model=Dict[str, Any])
async def get_report(report_id: UUID, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = await report_service.get_report(db, report_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return {"id": r.id, "kind": r.kind, "title": r.title, "content": r.content, "generated_by": r.generated_by,
            "created_at": r.created_at}


# ---------------------------------------------------------------------- search
@search_router.get("", response_model=Dict[str, Any])
async def search(q: str = Query(..., min_length=2, max_length=100), _: User = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)):
    return await search_service.search(db, q)
