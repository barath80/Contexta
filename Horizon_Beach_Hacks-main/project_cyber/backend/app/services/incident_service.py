"""
Contexta Backend - Incident Service
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.asset import Asset
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.log import LogSeverity, SecurityLog
from app.models.risk import Risk, RiskStatus
from app.risk_engine.ranking import risk_level

logger = structlog.get_logger()

ACTIVE_STATUSES = (
    IncidentStatus.OPEN, IncidentStatus.ANALYZING, IncidentStatus.RESPONDING, IncidentStatus.CONTAINED,
)
_SEV_FROM_LEVEL = {
    "critical": IncidentSeverity.CRITICAL, "high": IncidentSeverity.HIGH,
    "medium": IncidentSeverity.MEDIUM, "low": IncidentSeverity.LOW,
}


def _new_ref() -> str:
    return "INC-" + uuid.uuid4().hex[:8].upper()


class IncidentService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, incident_id: str | UUID) -> Optional[Incident]:
        try:
            iid = incident_id if isinstance(incident_id, UUID) else UUID(str(incident_id))
        except ValueError:
            return None
        return (
            await self.db.execute(select(Incident).options(selectinload(Incident.risk)).where(Incident.id == iid))
        ).scalar_one_or_none()

    async def create(
        self, *, title: str, description: Optional[str], severity: IncidentSeverity, created_by: UUID,
        risk_id: Optional[UUID] = None, incident_type: str = "security_incident", assigned_to: Optional[str] = None,
        affected_assets: Optional[List[UUID]] = None, iocs: Optional[Dict[str, Any]] = None, actor_label: str = "",
    ) -> Incident:
        inc = Incident(
            ref=_new_ref(), title=title, description=description, severity=severity, risk_id=risk_id,
            incident_type=incident_type, created_by=created_by, assigned_to=assigned_to,
            affected_assets=[str(a) for a in (affected_assets or [])], iocs=iocs or {}, status=IncidentStatus.OPEN,
            timeline=[],
        )
        inc.add_timeline_event("Incident created", f"Severity: {severity.value}", actor_label)
        self.db.add(inc)
        await self.db.flush()
        return inc

    async def create_from_risk(self, risk: Risk, created_by: UUID, actor_label: str, assigned_to: Optional[str] = None) -> Incident:
        existing = (
            await self.db.execute(
                select(Incident).where(Incident.risk_id == risk.id, Incident.status.in_(ACTIVE_STATUSES))
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        iocs = await self._collect_iocs(risk)
        kind = "vulnerability_exploitation" if risk.cve_id else (risk.category or "security_incident")
        inc = await self.create(
            title=f"Investigate: {risk.title}",
            description=risk.description,
            severity=_SEV_FROM_LEVEL[risk_level(risk.bwvs_score or 0)],
            created_by=created_by, risk_id=risk.id, incident_type=kind, assigned_to=assigned_to,
            affected_assets=[risk.asset_id] if risk.asset_id else [], iocs=iocs, actor_label=actor_label,
        )
        inc.add_timeline_event("Linked to risk", f"BWVS {risk.bwvs_score:.1f}, priority {risk.priority_score:.1f}", actor_label)
        risk.status = RiskStatus.INVESTIGATING
        await self.db.flush()
        return inc

    async def _collect_iocs(self, risk: Risk) -> Dict[str, Any]:
        iocs: Dict[str, List[str]] = {"ips": [], "domains": [], "hashes": [], "users": []}
        if risk.asset_id:
            rows = await self.db.execute(
                select(SecurityLog).where(
                    SecurityLog.asset_id == risk.asset_id,
                    SecurityLog.severity.in_([LogSeverity.MEDIUM, LogSeverity.HIGH, LogSeverity.CRITICAL]),
                ).order_by(SecurityLog.created_at.desc()).limit(50)
            )
            for log in rows.scalars().all():
                ind = log.indicators or {}
                for key, bucket in (("ips", "ips"), ("domains", "domains"), ("file_hashes", "hashes"), ("hashes", "hashes")):
                    for v in ind.get(key, []) or []:
                        if v not in iocs[bucket]:
                            iocs[bucket].append(v)
                if log.source_ip and log.source_ip not in iocs["ips"]:
                    iocs["ips"].append(log.source_ip)
        return {k: v[:25] for k, v in iocs.items() if v}

    async def list(
        self, page: int = 1, page_size: int = 50, status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None, active_only: bool = False, q: Optional[str] = None,
    ) -> Tuple[List[Incident], int]:
        query = select(Incident).options(selectinload(Incident.risk))
        count_q = select(func.count(Incident.id))
        conds = []
        if status:
            conds.append(Incident.status == status)
        elif active_only:
            conds.append(Incident.status.in_(ACTIVE_STATUSES))
        if severity:
            conds.append(Incident.severity == severity)
        if q:
            conds.append(or_(Incident.title.ilike(f"%{q}%"), Incident.ref.ilike(f"%{q}%")))
        for c in conds:
            query, count_q = query.where(c), count_q.where(c)
        total = (await self.db.execute(count_q)).scalar() or 0
        rows = (
            await self.db.execute(query.order_by(Incident.created_at.desc()).offset((page - 1) * page_size).limit(page_size))
        ).scalars().all()
        return list(rows), total

    async def update(self, inc: Incident, data: Dict[str, Any], actor_label: str) -> Incident:
        old_status, old_sev, old_assignee = inc.status, inc.severity, inc.assigned_to
        if "affected_assets" in data and data["affected_assets"] is not None:
            data["affected_assets"] = [str(a) for a in data["affected_assets"]]
        for k, v in data.items():
            setattr(inc, k, v)
        if inc.status != old_status:
            inc.add_timeline_event(f"Status changed to {inc.status.value}", f"from {old_status.value}", actor_label)
            if inc.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED) and not inc.resolved_at:
                inc.resolved_at = datetime.utcnow()
            elif inc.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                inc.resolved_at = None
        if inc.severity != old_sev:
            inc.add_timeline_event(f"Severity changed to {inc.severity.value}", f"from {old_sev.value}", actor_label)
        if inc.assigned_to != old_assignee:
            inc.add_timeline_event("Assignee changed", inc.assigned_to or "unassigned", actor_label)
        inc.updated_at = datetime.utcnow()
        await self.db.flush()
        return inc

    async def add_note(self, inc: Incident, note: str, actor_label: str) -> Incident:
        inc.add_timeline_event("Note added", note, actor_label)
        inc.updated_at = datetime.utcnow()
        await self.db.flush()
        return inc

    async def close(self, inc: Incident, resolution: str, resolve_risk: bool, actor_label: str) -> Incident:
        inc.status = IncidentStatus.CLOSED
        inc.resolution = resolution
        inc.resolved_at = datetime.utcnow()
        inc.add_timeline_event("Incident closed", resolution, actor_label)
        if resolve_risk and inc.risk_id:
            risk = (await self.db.execute(select(Risk).where(Risk.id == inc.risk_id))).scalar_one_or_none()
            if risk and risk.status != RiskStatus.RESOLVED:
                risk.status = RiskStatus.RESOLVED
                risk.resolved_at = datetime.utcnow()
                risk.is_top_10 = False
                inc.add_timeline_event("Linked risk resolved", risk.title, actor_label)
        await self.db.flush()
        return inc

    async def serialize(self, incidents: List[Incident]) -> List[Dict[str, Any]]:
        asset_ids: set = set()
        for i in incidents:
            for a in i.affected_assets or []:
                try:
                    asset_ids.add(UUID(a))
                except ValueError:
                    pass
        names: Dict[str, str] = {}
        if asset_ids:
            rows = await self.db.execute(select(Asset.id, Asset.name).where(Asset.id.in_(asset_ids)))
            names = {str(i): n for i, n in rows.all()}
        out = []
        for i in incidents:
            out.append({
                "id": i.id, "ref": i.ref, "title": i.title, "description": i.description,
                "incident_type": i.incident_type or "security_incident", "risk_id": i.risk_id,
                "risk_title": i.risk.title if i.risk else None, "risk_bwvs": i.risk.bwvs_score if i.risk else None,
                "status": i.status, "severity": i.severity, "created_by": i.created_by,
                "assigned_to": i.assigned_to, "timeline": i.timeline or [],
                "affected_assets": i.affected_assets or [],
                "affected_asset_names": [names[a] for a in (i.affected_assets or []) if a in names],
                "iocs": i.iocs or {}, "notes": i.notes, "resolution": i.resolution,
                "resolved_at": i.resolved_at, "created_at": i.created_at, "updated_at": i.updated_at,
            })
        return out

    async def statistics(self) -> Dict[str, Any]:
        rows = (await self.db.execute(select(Incident))).scalars().all()
        by_status: Dict[str, int] = {}
        for i in rows:
            by_status[i.status.value] = by_status.get(i.status.value, 0) + 1
        durations = [
            (i.resolved_at - i.created_at).total_seconds() / 3600
            for i in rows if i.resolved_at and i.created_at
        ]
        week_ago = datetime.utcnow() - timedelta(days=7)
        return {
            "total": len(rows),
            "active": sum(1 for i in rows if i.status in ACTIVE_STATUSES),
            "by_status": by_status,
            "critical_active": sum(1 for i in rows if i.status in ACTIVE_STATUSES and i.severity == IncidentSeverity.CRITICAL),
            "opened_last_7d": sum(1 for i in rows if i.created_at >= week_ago),
            "mttr_hours": round(sum(durations) / len(durations), 2) if durations else None,
        }
