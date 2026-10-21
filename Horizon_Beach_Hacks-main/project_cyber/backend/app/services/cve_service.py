"""
Contexta Backend - CVE Service
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.risk import Risk, RiskStatus

logger = structlog.get_logger()

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


class CVEService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_cve_id(self, cve_id: str) -> Optional[CVE]:
        return (await self.db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))).scalar_one_or_none()

    async def upsert(self, data: Dict[str, Any]) -> Tuple[CVE, bool]:
        """Insert or merge a normalised CVE record. Returns (cve, created)."""
        cve_id = data["cve_id"].upper()
        cve = await self.get_by_cve_id(cve_id)
        created = cve is None
        if created:
            cve = CVE(cve_id=cve_id, description=data.get("description") or "")
            self.db.add(cve)

        # Fields where the richer source (NVD) wins when it has data.
        if data.get("description") and (created or not cve.description or not data.get("cisa_kev")):
            cve.description = data["description"]
        if data.get("cvss_score"):
            cve.cvss_score = float(data["cvss_score"])
            cve.cvss_vector = data.get("cvss_vector") or cve.cvss_vector
        for field in ("attack_vector", "published_date", "last_modified"):
            if data.get(field) and (created or not getattr(cve, field)):
                setattr(cve, field, data[field])
        if data.get("last_modified"):
            cve.last_modified = data["last_modified"]

        merged = list(dict.fromkeys((cve.affected_software or []) + (data.get("affected_software") or [])))
        cve.affected_software = [s for s in merged if s and s.strip()]
        if data.get("version_ranges"):
            cve.version_ranges = data["version_ranges"]  # NVD is authoritative for version bounds
        sources = list(dict.fromkeys((cve.exploit_sources or []) + (data.get("exploit_sources") or [])))
        cve.exploit_sources = sources
        cve.has_exploit = bool(cve.has_exploit or data.get("has_exploit") or sources)
        if data.get("cisa_kev"):
            cve.cisa_kev = True
            cve.has_exploit = True
        if data.get("kev_ransomware_use"):
            cve.kev_ransomware_use = True
        if data.get("cwes"):
            cve.cwes = list(dict.fromkeys((cve.cwes or []) + data["cwes"]))
        refs = list(dict.fromkeys((cve.references or []) + (data.get("references") or [])))
        cve.references = refs[:15]

        cve.severity = severity_from_cvss(cve.cvss_score or 0) if cve.cvss_score else (cve.severity or data.get("severity"))
        await self.db.flush()
        return cve, created

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        severity: Optional[str] = None,
        min_cvss: Optional[float] = None,
        has_exploit: Optional[bool] = None,
        kev: Optional[bool] = None,
        q: Optional[str] = None,
        sort: str = "recent",
    ) -> Tuple[List[CVE], int]:
        query = select(CVE)
        count_q = select(func.count(CVE.id))
        conds = []
        if severity:
            conds.append(func.upper(CVE.severity) == severity.upper())
        if min_cvss is not None:
            conds.append(CVE.cvss_score >= min_cvss)
        if has_exploit is not None:
            conds.append(CVE.has_exploit == has_exploit)
        if kev is not None:
            conds.append(CVE.cisa_kev == kev)
        if q:
            conds.append(or_(CVE.cve_id.ilike(f"%{q}%"), CVE.description.ilike(f"%{q}%")))
        for c in conds:
            query, count_q = query.where(c), count_q.where(c)
        total = (await self.db.execute(count_q)).scalar() or 0
        order = {
            "cvss": CVE.cvss_score.desc(),
            "epss": CVE.epss_score.desc(),
            "recent": CVE.published_date.desc(),
        }.get(sort, CVE.published_date.desc())
        rows = (await self.db.execute(query.order_by(order).offset((page - 1) * page_size).limit(page_size))).scalars().all()
        return list(rows), total

    async def open_risk_counts(self, cve_ids) -> Dict[Any, int]:
        if not cve_ids:
            return {}
        rows = await self.db.execute(
            select(Risk.cve_id, func.count(Risk.id))
            .where(Risk.cve_id.in_(cve_ids), Risk.status.in_((RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)))
            .group_by(Risk.cve_id)
        )
        return {cid: n for cid, n in rows.all()}

    async def serialize(self, cves: List[CVE]) -> List[Dict[str, Any]]:
        counts = await self.open_risk_counts([c.id for c in cves])
        out = []
        for c in cves:
            out.append({
                "id": c.id, "cve_id": c.cve_id, "description": c.description or "",
                "cvss_score": c.cvss_score or 0.0, "cvss_vector": c.cvss_vector, "severity": c.severity,
                "affected_software": c.affected_software or [], "has_version_data": bool(c.version_ranges), "attack_vector": c.attack_vector,
                "published_date": c.published_date, "last_modified": c.last_modified,
                "has_exploit": bool(c.has_exploit), "exploit_sources": c.exploit_sources or [],
                "cisa_kev": bool(c.cisa_kev), "kev_ransomware_use": bool(c.kev_ransomware_use),
                "epss_score": c.epss_score, "epss_percentile": c.epss_percentile, "cwes": c.cwes or [],
                "references": c.references or [], "ai_extracted_data": c.ai_extracted_data or {},
                "exploit_activity_score": c.exploit_activity_score, "open_risks": counts.get(c.id, 0),
            })
        return out

    async def trending(self, limit: int = 10) -> List[CVE]:
        """CVEs that matter most right now: with open risks, exploited, high EPSS, recent."""
        rows = (
            await self.db.execute(
                select(CVE, func.count(Risk.id).label("risks"))
                .outerjoin(Risk, (Risk.cve_id == CVE.id) & Risk.status.in_(
                    (RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)))
                .group_by(CVE.id)
            )
        ).all()
        now = datetime.utcnow()

        def weight(row) -> float:
            c, risks = row
            age_days = max(0.0, (now - (c.published_date or now - timedelta(days=365))).total_seconds() / 86400)
            return (
                (c.cvss_score or 0) * 1.0
                + (8 if c.cisa_kev else 0)
                + (3 if c.has_exploit else 0)
                + 10 * (c.epss_score or 0)
                + min(risks, 5) * 3
                + 5 * (0.5 ** (age_days / 14))
            )

        ranked = sorted(rows, key=weight, reverse=True)
        return [c for c, _ in ranked[:limit]]

    async def statistics(self) -> Dict[str, Any]:
        total = (await self.db.execute(select(func.count(CVE.id)))).scalar() or 0
        by_sev = dict((await self.db.execute(select(func.upper(CVE.severity), func.count(CVE.id)).group_by(func.upper(CVE.severity)))).all())
        kev = (await self.db.execute(select(func.count(CVE.id)).where(CVE.cisa_kev == True))).scalar() or 0  # noqa: E712
        exploit = (await self.db.execute(select(func.count(CVE.id)).where(CVE.has_exploit == True))).scalar() or 0  # noqa: E712
        latest = (await self.db.execute(select(func.max(CVE.updated_at)))).scalar()
        return {
            "total": total, "by_severity": {k or "UNKNOWN": v for k, v in by_sev.items()},
            "cisa_kev": kev, "with_exploit": exploit,
            "last_updated": latest.isoformat() if latest else None,
        }
