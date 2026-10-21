"""
Contexta Backend - Risk routes
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_analyst
from app.config import settings
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.risk import Risk, RiskStatus
from app.models.user import User
from app.schemas.incident import IncidentResponse
from app.schemas.playbook import PlaybookRecommendation
from app.schemas.risk import RiskCreate, RiskListResponse, RiskResponse, RiskStatusUpdate, TopRisksResponse
from app.services import ledger_service
from app.services.asset_service import AssetService
from app.services.cve_service import CVEService
from app.services.incident_service import IncidentService
from app.services.playbook_service import PlaybookService
from app.services.risk_service import RiskService

router = APIRouter()


async def _get_or_404(svc: RiskService, risk_id: str) -> Risk:
    risk = await svc.get(risk_id)
    if risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk not found")
    return risk


@router.get("/top10", response_model=TopRisksResponse)
async def top_risks(limit: int = Query(10, ge=1, le=50), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = RiskService(db)
    risks = await svc.top(limit)
    return {
        "risks": await svc.serialize_many(risks),
        "last_calculated": max((r.updated_at for r in risks), default=datetime.utcnow()),
        "calculation_interval_minutes": settings.risk_calculation_interval_minutes,
    }


@router.get("/stats", response_model=Dict[str, Any])
async def risk_stats(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await RiskService(db).statistics()


@router.get("", response_model=RiskListResponse)
async def list_risks(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[RiskStatus] = Query(None, alias="status"),
    level: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    category: Optional[str] = None, asset_id: Optional[UUID] = None, min_bwvs: Optional[float] = Query(None, ge=0, le=100),
    q: Optional[str] = Query(None, max_length=100), open_only: bool = False,
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = RiskService(db)
    rows, total = await svc.list(page, page_size, status_filter, min_bwvs, level, category, asset_id, q, open_only)
    return {"items": await svc.serialize_many(rows), "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=RiskResponse, status_code=status.HTTP_201_CREATED)
async def create_risk(data: RiskCreate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    asset = await AssetService(db).get(data.asset_id) if data.asset_id else None
    if data.asset_id and asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    cve = None
    if data.cve_id:
        cve = await CVEService(db).get_by_cve_id(data.cve_id)
        if cve is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"{data.cve_id} is not in the CVE database")
    svc = RiskService(db)
    risk = await svc.create_manual(data.title, data.description, asset, cve)
    await ledger_service.record(LedgerEventTypes.RISK_CREATED, actor=user.email, resource_type="risk",
                                resource_id=str(risk.id), data={"title": risk.title, "bwvs": risk.bwvs_score})
    return await svc.serialize(risk)


@router.get("/{risk_id}", response_model=RiskResponse)
async def get_risk(risk_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = RiskService(db)
    return await svc.serialize(await _get_or_404(svc, risk_id))


@router.post("/{risk_id}/recalculate", response_model=RiskResponse)
async def recalculate(risk_id: str, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = RiskService(db)
    risk = await _get_or_404(svc, risk_id)
    events = await svc._event_counts([risk.asset_id] if risk.asset_id else [])
    await svc.score_risk(risk, events.get(risk.asset_id, (0, 0)), force_history=True)
    await ledger_service.record(LedgerEventTypes.RISK_CALCULATED, actor=user.email, resource_type="risk",
                                resource_id=str(risk.id), data={"bwvs": risk.bwvs_score, "priority": risk.priority_score})
    return await svc.serialize(risk)


@router.put("/{risk_id}/status", response_model=RiskResponse)
async def update_status(risk_id: str, data: RiskStatusUpdate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = RiskService(db)
    risk = await _get_or_404(svc, risk_id)
    old = risk.status
    await svc.set_status(risk, data.status, data.notes)
    await ledger_service.record(LedgerEventTypes.RISK_STATUS_CHANGED, actor=user.email, resource_type="risk",
                                resource_id=str(risk.id), data={"from": old.value, "to": data.status.value, "notes": data.notes})
    return await svc.serialize(risk)


@router.get("/{risk_id}/history", response_model=List[Dict[str, Any]])
async def score_history(risk_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = RiskService(db)
    risk = await _get_or_404(svc, risk_id)
    return [
        {"calculated_at": s.calculation_timestamp, "bwvs": s.final_bwvs, "cvss": s.cvss_score,
         "exploit": s.exploit_activity, "exposure": s.exposure_level, "criticality": s.asset_criticality,
         "business_impact": s.business_impact, "ai_relevance": s.ai_relevance}
        for s in reversed(await svc.score_history(risk.id))
    ]


@router.get("/{risk_id}/playbooks", response_model=List[PlaybookRecommendation])
async def recommended_playbooks(risk_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    risk = await _get_or_404(RiskService(db), risk_id)
    pbs = PlaybookService(db)
    return [{"playbook": pbs.serialize(pb), "score": score, "reasons": reasons} for pb, score, reasons in await pbs.recommend(risk, 5)]


@router.post("/{risk_id}/investigate", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def investigate(risk_id: str, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Open (or return the existing) incident for a risk and mark the risk as investigating."""
    risk = await _get_or_404(RiskService(db), risk_id)
    svc = IncidentService(db)
    inc = await svc.create_from_risk(risk, user.id, user.email)
    await ledger_service.record(LedgerEventTypes.INCIDENT_CREATED, actor=user.email, resource_type="incident",
                                resource_id=str(inc.id), data={"ref": inc.ref, "risk_id": str(risk.id), "severity": inc.severity.value})
    return (await svc.serialize([inc]))[0]
