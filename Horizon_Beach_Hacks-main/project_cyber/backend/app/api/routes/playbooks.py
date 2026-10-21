"""
Contexta Backend - Playbook routes
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_admin, require_analyst
from app.database import get_db
from app.models.playbook import PlaybookStatus
from app.models.user import User
from app.schemas.playbook import (
    ExecutionResponse, ExecutionStart, PlaybookCreate, PlaybookResponse, PlaybookUpdate, StepComplete,
)
from app.services.incident_service import IncidentService
from app.services.playbook_service import PlaybookError, PlaybookService
from app.services.risk_service import RiskService

router = APIRouter()


def _http(exc: PlaybookError) -> HTTPException:
    return HTTPException(exc.status_code, str(exc))


# ------------------------------------------------------------- executions
@router.get("/executions", response_model=dict)
async def list_executions(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[PlaybookStatus] = Query(None, alias="status"), risk_id: Optional[UUID] = None,
    incident_id: Optional[UUID] = None, playbook_id: Optional[UUID] = None,
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = PlaybookService(db)
    rows, total = await svc.list_executions(page, page_size, status_filter, risk_id, incident_id, playbook_id)
    items = [ExecutionResponse(**(await svc.serialize_execution(r))).model_dump(mode="json") for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/executions", response_model=ExecutionResponse, status_code=status.HTTP_201_CREATED)
async def start_execution(data: ExecutionStart, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    ident = data.playbook_id or data.slug
    if ident is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide playbook_id or slug")
    playbook = await svc.get(ident)
    if playbook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    risk = await RiskService(db).get(data.risk_id) if data.risk_id else None
    incident = await IncidentService(db).get(data.incident_id) if data.incident_id else None
    if data.risk_id and risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk not found")
    if data.incident_id and incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    try:
        ex = await svc.start(playbook, user, risk, incident, data.resolve_risk, data.parameters)
    except PlaybookError as exc:
        raise _http(exc)
    return await svc.serialize_execution(ex)


@router.get("/executions/{execution_id}", response_model=ExecutionResponse)
async def get_execution(execution_id: UUID, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    ex = await svc.get_execution(execution_id)
    if ex is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Execution not found")
    return await svc.serialize_execution(ex)


async def _step(execution_id: UUID, order: int, data: StepComplete, user: User, db: AsyncSession, skip: bool):
    svc = PlaybookService(db)
    ex = await svc.get_execution(execution_id)
    if ex is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Execution not found")
    try:
        await svc.complete_step(ex, order, user, data.notes, skip=skip)
    except PlaybookError as exc:
        raise _http(exc)
    return await svc.serialize_execution(ex)


@router.post("/executions/{execution_id}/steps/{order}/complete", response_model=ExecutionResponse)
async def complete_step(execution_id: UUID, order: int, data: StepComplete = StepComplete(),
                        user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    return await _step(execution_id, order, data, user, db, skip=False)


@router.post("/executions/{execution_id}/steps/{order}/skip", response_model=ExecutionResponse)
async def skip_step(execution_id: UUID, order: int, data: StepComplete = StepComplete(),
                    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    return await _step(execution_id, order, data, user, db, skip=True)


@router.post("/executions/{execution_id}/cancel", response_model=ExecutionResponse)
async def cancel_execution(execution_id: UUID, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    ex = await svc.get_execution(execution_id)
    if ex is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Execution not found")
    try:
        await svc.cancel(ex, user)
    except PlaybookError as exc:
        raise _http(exc)
    return await svc.serialize_execution(ex)


# ------------------------------------------------------------- definitions
@router.get("", response_model=List[PlaybookResponse])
async def list_playbooks(active_only: bool = False, category: Optional[str] = None,
                         _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    return [svc.serialize(p) for p in await svc.list(active_only, category)]


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(data: PlaybookCreate, _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    try:
        pb = await svc.create(data.model_dump())
    except PlaybookError as exc:
        raise _http(exc)
    return svc.serialize(pb)


@router.get("/{ident}", response_model=PlaybookResponse)
async def get_playbook(ident: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    pb = await svc.get(ident)
    if pb is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    return svc.serialize(pb)


@router.patch("/{ident}", response_model=PlaybookResponse)
async def update_playbook(ident: str, data: PlaybookUpdate, _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    svc = PlaybookService(db)
    pb = await svc.get(ident)
    if pb is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    await svc.update(pb, data.model_dump(exclude_unset=True))
    return svc.serialize(pb)
