"""
Contexta Backend - Security log / alert service

Ingests events, resolves them to assets, correlates them into threat risks
and serves the alert feed.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.log import LogCategory, LogSeverity, SecurityLog
from app.models.risk import Risk, RiskStatus
from app.services.asset_service import AssetService
from app.services.risk_service import OPEN_STATUSES, RiskService

logger = structlog.get_logger()

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Events within 24h on one asset+category that turn into a threat risk.
THREAT_THRESHOLDS = {"critical": 1, "high": 3, "medium": 10}


def _sev(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


class LogService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.assets = AssetService(db)

    async def ingest(self, events: List[Dict[str, Any]], simulated: bool = False) -> Dict[str, int]:
        touched: Dict[UUID, Asset] = {}
        matched = 0
        cache: Dict[Tuple[Optional[str], Optional[str]], Optional[Asset]] = {}
        for ev in events:
            asset: Optional[Asset] = None
            if ev.get("asset_id"):
                asset = await self.assets.get(ev["asset_id"])
            if asset is None:
                key = (ev.get("destination_ip") or ev.get("source_ip"), ev.get("hostname"))
                if key not in cache:
                    cache[key] = await self.assets.find_by_address(ev.get("destination_ip"), ev.get("hostname")) \
                        or await self.assets.find_by_address(ev.get("source_ip"))
                asset = cache[key]
            indicators = ev.get("indicators") or {}
            if not indicators and ev.get("source_ip"):
                indicators = {"ips": [ev["source_ip"]]}
            log = SecurityLog(
                source=ev["source"], category=ev["category"], severity=ev["severity"], message=ev["message"],
                source_ip=ev.get("source_ip"), destination_ip=ev.get("destination_ip"),
                source_port=ev.get("source_port"), destination_port=ev.get("destination_port"),
                username=ev.get("username"), asset_id=asset.id if asset else None,
                raw_log=ev.get("raw_log") or {}, indicators=indicators, is_simulated=simulated, status="new",
                is_correlated="true" if asset else "false",
            )
            if ev.get("occurred_at"):
                log.created_at = ev["occurred_at"]
            self.db.add(log)
            if asset:
                matched += 1
                touched[asset.id] = asset
        await self.db.flush()

        created = updated = 0
        for asset in touched.values():
            c, u = await self.correlate_asset(asset)
            created, updated = created + c, updated + u
        return {"ingested": len(events), "matched_to_assets": matched,
                "risks_created": created, "risks_updated": updated}

    async def correlate_asset(self, asset: Asset) -> Tuple[int, int]:
        """Turn clustered high-severity events into threat risks; refresh CVE-risk evidence."""
        since = datetime.utcnow() - timedelta(hours=24)
        rows = (
            await self.db.execute(
                select(SecurityLog.category, SecurityLog.severity, func.count(SecurityLog.id))
                .where(SecurityLog.asset_id == asset.id, SecurityLog.created_at >= since,
                       SecurityLog.status != "dismissed")
                .group_by(SecurityLog.category, SecurityLog.severity)
            )
        ).all()
        per_cat: Dict[str, Dict[str, int]] = {}
        for cat, sev, n in rows:
            per_cat.setdefault(_sev(cat), {})[_sev(sev)] = n

        risks = RiskService(self.db)
        created = updated = 0
        for cat, sevs in per_cat.items():
            worst = max(sevs, key=lambda s: SEVERITY_RANK[s])
            qualifying = sum(n for s, n in sevs.items() if SEVERITY_RANK[s] >= SEVERITY_RANK["medium"])
            threshold = THREAT_THRESHOLDS.get(worst)
            if not threshold or qualifying < threshold:
                continue
            latest = (
                await self.db.execute(
                    select(SecurityLog.message).where(SecurityLog.asset_id == asset.id, SecurityLog.category == LogCategory(cat))
                    .order_by(SecurityLog.created_at.desc()).limit(1)
                )
            ).scalar_one_or_none() or ""
            _, is_new = await risks.upsert_threat_risk(asset, cat, worst, qualifying, latest[:300])
            created, updated = created + int(is_new), updated + int(not is_new)

        # New evidence against an asset keeps its open vulnerability risks fresh.
        open_vuln = (
            await self.db.execute(
                select(Risk).where(Risk.asset_id == asset.id, Risk.source == "cve_correlation",
                                   Risk.status.in_(OPEN_STATUSES))
            )
        ).scalars().all()
        if per_cat and open_vuln:
            for r in open_vuln:
                r.last_seen = datetime.utcnow()
        await self.db.flush()
        return created, updated

    # ------------------------------------------------------------------ feed
    def _conditions(
        self,
        min_severity: Optional[str],
        status: Optional[str],
        category: Optional[str],
        asset_id: Optional[UUID],
        q: Optional[str],
        since: Optional[datetime],
    ):
        conds = []
        if min_severity:
            allowed = [LogSeverity(s) for s, r in SEVERITY_RANK.items() if r >= SEVERITY_RANK[min_severity]]
            conds.append(SecurityLog.severity.in_(allowed))
        if status:
            conds.append(SecurityLog.status == status)
        if category:
            conds.append(SecurityLog.category == LogCategory(category))
        if asset_id:
            conds.append(SecurityLog.asset_id == asset_id)
        if q:
            like = f"%{q}%"
            conds.append(or_(SecurityLog.message.ilike(like), SecurityLog.source_ip.ilike(like),
                             SecurityLog.destination_ip.ilike(like), SecurityLog.username.ilike(like)))
        if since:
            conds.append(SecurityLog.created_at >= since)
        return conds

    async def list_alerts(
        self,
        page: int = 1,
        page_size: int = 50,
        min_severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        asset_id: Optional[UUID] = None,
        q: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        conds = self._conditions(min_severity, status, category, asset_id, q, since)
        query = select(SecurityLog, Asset.name).outerjoin(Asset, Asset.id == SecurityLog.asset_id)
        count_q = select(func.count(SecurityLog.id))
        for c in conds:
            query, count_q = query.where(c), count_q.where(c)
        total = (await self.db.execute(count_q)).scalar() or 0
        rows = (
            await self.db.execute(query.order_by(SecurityLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size))
        ).all()
        return [self.serialize(log, name) for log, name in rows], total

    @staticmethod
    def serialize(log: SecurityLog, asset_name: Optional[str]) -> Dict[str, Any]:
        return {
            "id": log.id, "source": log.source, "category": _sev(log.category), "severity": _sev(log.severity),
            "message": log.message, "source_ip": log.source_ip, "destination_ip": log.destination_ip,
            "destination_port": log.destination_port, "username": log.username, "asset_id": log.asset_id,
            "asset_name": asset_name, "status": log.status or "new", "is_simulated": bool(log.is_simulated),
            "indicators": log.indicators or {}, "raw_log": log.raw_log or {}, "created_at": log.created_at,
        }

    async def get(self, log_id: UUID) -> Optional[SecurityLog]:
        return (await self.db.execute(select(SecurityLog).where(SecurityLog.id == log_id))).scalar_one_or_none()

    async def set_status(self, log: SecurityLog, status: str, user_id: UUID) -> SecurityLog:
        log.status = status
        log.acknowledged_by = user_id
        await self.db.flush()
        return log

    async def unread_count(self, since: Optional[datetime], min_severity: str = "high") -> int:
        conds = self._conditions(min_severity, "new", None, None, None, since)
        q = select(func.count(SecurityLog.id))
        for c in conds:
            q = q.where(c)
        return (await self.db.execute(q)).scalar() or 0

    async def statistics(self, hours: int = 24) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(hours=hours)
        by_sev = dict(
            (_sev(s), n) for s, n in (
                await self.db.execute(
                    select(SecurityLog.severity, func.count(SecurityLog.id)).where(SecurityLog.created_at >= since)
                    .group_by(SecurityLog.severity)
                )
            ).all()
        )
        by_cat = dict(
            (_sev(c), n) for c, n in (
                await self.db.execute(
                    select(SecurityLog.category, func.count(SecurityLog.id)).where(SecurityLog.created_at >= since)
                    .group_by(SecurityLog.category)
                )
            ).all()
        )
        top_ips = (
            await self.db.execute(
                select(SecurityLog.source_ip, func.count(SecurityLog.id).label("n"))
                .where(SecurityLog.created_at >= since, SecurityLog.source_ip != None)  # noqa: E711
                .group_by(SecurityLog.source_ip).order_by(func.count(SecurityLog.id).desc()).limit(5)
            )
        ).all()
        return {
            "window_hours": hours, "total": sum(by_sev.values()), "by_severity": by_sev, "by_category": by_cat,
            "top_source_ips": [{"ip": ip, "events": n} for ip, n in top_ips],
        }

    async def recent_for_asset(self, asset_id: UUID, limit: int = 25) -> List[SecurityLog]:
        rows = await self.db.execute(
            select(SecurityLog).where(SecurityLog.asset_id == asset_id)
            .order_by(SecurityLog.created_at.desc()).limit(limit)
        )
        return list(rows.scalars().all())
