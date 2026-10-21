"""
Contexta Backend - Asset routes
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_admin, require_analyst
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.asset import Asset, AssetCriticality, AssetType, ExposureLevel
from app.models.user import User
from app.schemas.asset import (
    AssetCreate, AssetImport, AssetResponse, AssetUpdate, ConnectionCreate, ConnectionResponse,
)
from app.schemas.log import AlertResponse
from app.schemas.risk import RiskResponse
from app.services import ledger_service
from app.services.asset_service import AssetConflict, AssetService
from app.services.log_service import LogService
from app.services.risk_service import RiskService

router = APIRouter()


async def _get_or_404(svc: AssetService, asset_id: str) -> Asset:
    asset = await svc.get(asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


async def _correlate(db: AsyncSession, asset: Asset) -> int:
    risks = RiskService(db)
    created = await risks.correlate_asset(asset)
    await risks.refresh_all()
    return created


@router.get("/stats", response_model=Dict[str, Any])
async def stats(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await AssetService(db).statistics()


@router.get("", response_model=Dict[str, Any])
async def list_assets(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    asset_type: Optional[AssetType] = None, criticality: Optional[AssetCriticality] = None,
    exposure: Optional[ExposureLevel] = None, business_unit: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=100),
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    svc = AssetService(db)
    rows, total = await svc.list(page, page_size, asset_type, criticality, exposure, business_unit, q)
    return {"items": [AssetResponse(**a).model_dump(mode="json") for a in await svc.serialize(rows)],
            "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(data: AssetCreate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    try:
        asset = await svc.create(data.model_dump())
    except AssetConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    created = await _correlate(db, asset)
    await ledger_service.record(LedgerEventTypes.ASSET_CREATED, actor=user.email, resource_type="asset",
                                resource_id=str(asset.id), data={"name": asset.name, "risks_created": created})
    return (await svc.serialize([asset]))[0]


@router.post("/import", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def import_assets(data: AssetImport, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    created, skipped = [], []
    for item in data.assets:
        try:
            created.append(await svc.create(item.model_dump()))
        except AssetConflict as exc:
            skipped.append({"name": item.name, "reason": str(exc)})
    risks = RiskService(db)
    new_risks = 0
    for a in created:
        new_risks += await risks.correlate_asset(a)
    if created:
        await risks.refresh_all()
    await ledger_service.record(LedgerEventTypes.ASSET_CREATED, actor=user.email, resource_type="asset",
                                data={"bulk_import": len(created), "skipped": len(skipped), "risks_created": new_risks})
    return {"created": len(created), "skipped": skipped, "risks_created": new_risks}


@router.get("/connections", response_model=List[ConnectionResponse])
async def list_connections(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await AssetService(db).list_connections()


@router.post("/connections", response_model=ConnectionResponse, status_code=status.HTTP_201_CREATED)
async def add_connection(data: ConnectionCreate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    for aid in (data.source_asset_id, data.target_asset_id):
        if await svc.get(aid) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Asset {aid} not found")
    try:
        return await svc.add_connection(data.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(connection_id: UUID, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    if not await AssetService(db).delete_connection(connection_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Connection not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    return (await svc.serialize([await _get_or_404(svc, asset_id)]))[0]


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, data: AssetUpdate, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    asset = await _get_or_404(svc, asset_id)
    changes = data.model_dump(exclude_unset=True)
    try:
        await svc.update(asset, changes)
    except AssetConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if {"software", "os", "exposure_level", "criticality", "daily_revenue_impact", "is_active"} & set(changes):
        await _correlate(db, asset)
    await ledger_service.record(LedgerEventTypes.ASSET_UPDATED, actor=user.email, resource_type="asset",
                                resource_id=str(asset.id), data={"fields": sorted(changes)})
    return (await svc.serialize([asset]))[0]


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    asset = await _get_or_404(svc, asset_id)
    name = asset.name
    await svc.delete(asset)
    await ledger_service.record(LedgerEventTypes.ASSET_DELETED, actor=user.email, resource_type="asset",
                                resource_id=asset_id, data={"name": name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{asset_id}/risks", response_model=List[RiskResponse])
async def asset_risks(asset_id: str, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    asset = await _get_or_404(AssetService(db), asset_id)
    svc = RiskService(db)
    rows, _total = await svc.list(page=1, page_size=200, asset_id=asset.id)
    return await svc.serialize_many(rows)


@router.get("/{asset_id}/events", response_model=List[AlertResponse])
async def asset_events(asset_id: str, limit: int = Query(50, ge=1, le=200), _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    asset = await _get_or_404(AssetService(db), asset_id)
    items, _total = await LogService(db).list_alerts(page=1, page_size=limit, asset_id=asset.id)
    return items


@router.post("/{asset_id}/isolate", response_model=AssetResponse)
async def isolate(asset_id: str, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    asset = await svc.set_isolation(await _get_or_404(svc, asset_id), True)
    await ledger_service.record(LedgerEventTypes.ASSET_ISOLATED, actor=user.email, resource_type="asset",
                                resource_id=str(asset.id), data={"name": asset.name, "manual": True})
    return (await svc.serialize([asset]))[0]


@router.post("/{asset_id}/restore", response_model=AssetResponse)
async def restore(asset_id: str, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    svc = AssetService(db)
    asset = await svc.set_isolation(await _get_or_404(svc, asset_id), False)
    await ledger_service.record(LedgerEventTypes.ASSET_RESTORED, actor=user.email, resource_type="asset",
                                resource_id=str(asset.id), data={"name": asset.name})
    return (await svc.serialize([asset]))[0]
