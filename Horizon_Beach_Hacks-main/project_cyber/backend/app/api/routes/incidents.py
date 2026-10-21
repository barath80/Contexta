"""
Contexta Backend - Incident routes
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_analyst
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User
from app.schemas.incident import (
    IncidentClose, IncidentCreate, IncidentFromRisk, IncidentListResponse, IncidentNote, IncidentResponse,
    IncidentUpdate,
)
from app.services import ledger_service
from app.services.incident_service import IncidentService
from app.services.risk_service import RiskService

router = APIRouter()


async def _get_or_404(svc: IncidentService, incident_id: str) -> Incident:
    inc = await svc.get(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


@router.get("/stats", response_model=Dict[str, Any])
async def stats(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await IncidentService(db).statistics()


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"), severity: Optional[IncidentSeverity] = None,
    active_only: bool = False, q: Optional[str] = Query(None, max_length=100),
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = IncidentService(db)
    rows, total = await svc.list(page, page_size, status_filter, severity, active_only, q)
    return {"items": await svc.serialize(rows), "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(data: IncidentCreate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    if data.risk_id and await RiskService(db).get(data.risk_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk not found")
    svc = IncidentService(db)
    inc = await svc.create(
        title=data.title, description=data.description, severity=data.severity, created_by=user.id,
        risk_id=data.risk_id, incident_type=data.incident_type, assigned_to=data.assigned_to,
        affected_assets=data.affected_assets, iocs=data.iocs, actor_label=user.email,
    )
    await ledger_service.record(LedgerEventTypes.INCIDENT_CREATED, actor=user.email, resource_type="incident",
                                resource_id=str(inc.id), data={"ref": inc.ref, "title": inc.title, "severity": inc.severity.value})
    return (await svc.serialize([inc]))[0]


@router.post("/from-risk", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def from_risk(data: IncidentFromRisk, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    risk = await RiskService(db).get(data.risk_id)
    if risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk not found")
    svc = IncidentService(db)
    inc = await svc.create_from_risk(risk, user.id, user.email, data.assigned_to)
    await ledger_service.record(LedgerEventTypes.INCIDENT_CREATED, actor=user.email, resource_type="incident",
                                resource_id=str(inc.id), data={"ref": inc.ref, "risk_id": str(risk.id)})
    return (await svc.serialize([inc]))[0]


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = IncidentService(db)
    return (await svc.serialize([await _get_or_404(svc, incident_id)]))[0]


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: str, data: IncidentUpdate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = IncidentService(db)
    inc = await _get_or_404(svc, incident_id)
    changes = data.model_dump(exclude_unset=True)
    await svc.update(inc, changes, user.email)
    await ledger_service.record(LedgerEventTypes.INCIDENT_UPDATED, actor=user.email, resource_type="incident",
                                resource_id=str(inc.id), data={"fields": sorted(changes), "status": inc.status.value})
    return (await svc.serialize([inc]))[0]


@router.post("/{incident_id}/notes", response_model=IncidentResponse)
async def add_note(incident_id: str, data: IncidentNote, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = IncidentService(db)
    inc = await svc.add_note(await _get_or_404(svc, incident_id), data.note, user.email)
    return (await svc.serialize([inc]))[0]


@router.post("/{incident_id}/close", response_model=IncidentResponse)
async def close_incident(incident_id: str, data: IncidentClose, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = IncidentService(db)
    inc = await _get_or_404(svc, incident_id)
    if inc.status == IncidentStatus.CLOSED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is already closed")
    await svc.close(inc, data.resolution, data.resolve_risk, user.email)
    await ledger_service.record(LedgerEventTypes.INCIDENT_CLOSED, actor=user.email, resource_type="incident",
                                resource_id=str(inc.id), data={"ref": inc.ref, "resolution": data.resolution[:500]})
    return (await svc.serialize([inc]))[0]
