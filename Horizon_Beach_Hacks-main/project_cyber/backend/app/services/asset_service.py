"""
Contexta Backend - Asset Service
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetCriticality, AssetType, ExposureLevel
from app.models.extras import AssetConnection
from app.models.risk import Risk, RiskStatus
from app.risk_engine.ranking import risk_level

logger = structlog.get_logger()

OPEN = (RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)


class AssetConflict(Exception):
    """Hostname already registered."""


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, asset_id: str | UUID) -> Optional[Asset]:
        try:
            aid = asset_id if isinstance(asset_id, UUID) else UUID(str(asset_id))
        except ValueError:
            return None
        return (await self.db.execute(select(Asset).where(Asset.id == aid))).scalar_one_or_none()

    async def get_by_hostname(self, hostname: str) -> Optional[Asset]:
        return (await self.db.execute(select(Asset).where(Asset.hostname == hostname))).scalar_one_or_none()

    async def find_by_address(self, ip: Optional[str], hostname: Optional[str] = None) -> Optional[Asset]:
        conds = []
        if ip:
            conds.append(Asset.ip_address == ip)
        if hostname:
            conds.append(Asset.hostname == hostname)
        if not conds:
            return None
        return (await self.db.execute(select(Asset).where(or_(*conds)).limit(1))).scalar_one_or_none()

    async def create(self, data: Dict[str, Any]) -> Asset:
        if data.get("hostname") and await self.get_by_hostname(data["hostname"]):
            raise AssetConflict(f"Hostname '{data['hostname']}' already exists")
        asset = Asset(**data)
        self.db.add(asset)
        await self.db.flush()
        return asset

    async def update(self, asset: Asset, data: Dict[str, Any]) -> Asset:
        hostname = data.get("hostname")
        if hostname and hostname != asset.hostname:
            existing = await self.get_by_hostname(hostname)
            if existing and existing.id != asset.id:
                raise AssetConflict(f"Hostname '{hostname}' already exists")
        for k, v in data.items():
            setattr(asset, k, v)
        asset.updated_at = datetime.utcnow()
        await self.db.flush()
        return asset

    async def delete(self, asset: Asset) -> None:
        # Detach dependent rows that must not block deletion.
        from app.models.log import SecurityLog

        for risk in (await self.db.execute(select(Risk).where(Risk.asset_id == asset.id))).scalars().all():
            await self.db.delete(risk)
        for log in (await self.db.execute(select(SecurityLog).where(SecurityLog.asset_id == asset.id))).scalars().all():
            log.asset_id = None
        for conn in (
            await self.db.execute(
                select(AssetConnection).where(
                    or_(AssetConnection.source_asset_id == asset.id, AssetConnection.target_asset_id == asset.id)
                )
            )
        ).scalars().all():
            await self.db.delete(conn)
        await self.db.delete(asset)
        await self.db.flush()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[AssetCriticality] = None,
        exposure: Optional[ExposureLevel] = None,
        business_unit: Optional[str] = None,
        q: Optional[str] = None,
        active_only: bool = False,
    ) -> Tuple[List[Asset], int]:
        query, count_q = select(Asset), select(func.count(Asset.id))
        conds = []
        if asset_type:
            conds.append(Asset.asset_type == asset_type)
        if criticality:
            conds.append(Asset.criticality == criticality)
        if exposure:
            conds.append(Asset.exposure_level == exposure)
        if business_unit:
            conds.append(Asset.business_unit == business_unit)
        if active_only:
            conds.append(Asset.is_active == True)  # noqa: E712
        if q:
            like = f"%{q}%"
            conds.append(or_(Asset.name.ilike(like), Asset.hostname.ilike(like), Asset.ip_address.ilike(like),
                             Asset.owner.ilike(like)))
        for c in conds:
            query, count_q = query.where(c), count_q.where(c)
        total = (await self.db.execute(count_q)).scalar() or 0
        rows = (await self.db.execute(query.order_by(Asset.name).offset((page - 1) * page_size).limit(page_size))).scalars().all()
        return list(rows), total

    async def risk_summary(self, asset_ids: List[UUID]) -> Dict[UUID, Tuple[int, float]]:
        if not asset_ids:
            return {}
        rows = await self.db.execute(
            select(Risk.asset_id, func.count(Risk.id), func.max(Risk.bwvs_score))
            .where(Risk.asset_id.in_(asset_ids), Risk.status.in_(OPEN)).group_by(Risk.asset_id)
        )
        return {aid: (n, mx or 0.0) for aid, n, mx in rows.all()}

    async def serialize(self, assets: List[Asset]) -> List[Dict[str, Any]]:
        summary = await self.risk_summary([a.id for a in assets])
        out = []
        for a in assets:
            n, mx = summary.get(a.id, (0, 0.0))
            out.append({
                "id": a.id, "name": a.name, "hostname": a.hostname, "ip_address": a.ip_address,
                "asset_type": a.asset_type, "os": a.os, "software": a.software or [],
                "exposure_level": a.exposure_level, "criticality": a.criticality,
                "network_zone": a.network_zone or "internal", "business_unit": a.business_unit,
                "owner": a.owner, "location": a.location, "daily_revenue_impact": a.daily_revenue_impact or 0.0,
                "is_active": bool(a.is_active), "is_isolated": bool(a.is_isolated), "isolated_at": a.isolated_at,
                "asset_metadata": a.asset_metadata or {}, "exposure_score": a.exposure_score,
                "criticality_score": a.criticality_score, "business_impact_score": a.business_impact_score,
                "open_risks": n, "max_bwvs": round(mx, 2), "risk_level": risk_level(mx) if n else "none",
                "created_at": a.created_at, "updated_at": a.updated_at,
            })
        return out

    async def statistics(self) -> Dict[str, Any]:
        assets = (await self.db.execute(select(Asset))).scalars().all()
        by_type: Dict[str, int] = {}
        for a in assets:
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
        return {
            "total": len(assets),
            "active": sum(1 for a in assets if a.is_active),
            "isolated": sum(1 for a in assets if a.is_isolated),
            "internet_facing": sum(1 for a in assets if a.exposure_level == ExposureLevel.INTERNET_FACING),
            "critical": sum(1 for a in assets if a.criticality in (AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND)),
            "by_type": by_type,
        }

    async def count(self) -> int:
        return (await self.db.execute(select(func.count(Asset.id)))).scalar() or 0

    # ------------------------------------------------------------ connections
    async def list_connections(self) -> List[AssetConnection]:
        return list((await self.db.execute(select(AssetConnection))).scalars().all())

    async def add_connection(self, data: Dict[str, Any]) -> AssetConnection:
        if data["source_asset_id"] == data["target_asset_id"]:
            raise ValueError("An asset cannot connect to itself")
        existing = (
            await self.db.execute(
                select(AssetConnection).where(
                    AssetConnection.source_asset_id == data["source_asset_id"],
                    AssetConnection.target_asset_id == data["target_asset_id"],
                )
            )
        ).scalar_one_or_none()
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
            await self.db.flush()
            return existing
        conn = AssetConnection(**data)
        self.db.add(conn)
        await self.db.flush()
        return conn

    async def delete_connection(self, conn_id: UUID) -> bool:
        conn = (await self.db.execute(select(AssetConnection).where(AssetConnection.id == conn_id))).scalar_one_or_none()
        if not conn:
            return False
        await self.db.delete(conn)
        await self.db.flush()
        return True

    # ----------------------------------------------------------- isolation
    async def set_isolation(self, asset: Asset, isolated: bool) -> Asset:
        asset.is_isolated = isolated
        asset.isolated_at = datetime.utcnow() if isolated else None
        await self.db.flush()
        return asset
