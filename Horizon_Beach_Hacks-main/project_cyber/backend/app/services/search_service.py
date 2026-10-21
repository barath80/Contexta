"""
Contexta Backend - Global search (CVE / IP / asset / risk / incident)
"""

import re
from typing import Any, Dict, List

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.cve import CVE
from app.models.incident import Incident
from app.models.log import SecurityLog
from app.models.risk import Risk

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){0,3}$|^[0-9a-fA-F:]+$")


async def search(db: AsyncSession, q: str, limit: int = 5) -> Dict[str, Any]:
    q = q.strip()
    like = f"%{q}%"
    out: Dict[str, List[Dict[str, Any]]] = {"cves": [], "assets": [], "risks": [], "incidents": [], "events": []}

    cves = (await db.execute(
        select(CVE).where(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
        .order_by(CVE.cvss_score.desc()).limit(limit)
    )).scalars().all()
    out["cves"] = [{"id": str(c.id), "title": c.cve_id, "subtitle": (c.description or "")[:90],
                    "badge": f"CVSS {c.cvss_score:.1f}" + (" - KEV" if c.cisa_kev else "")} for c in cves]

    assets = (await db.execute(
        select(Asset).where(or_(Asset.name.ilike(like), Asset.hostname.ilike(like), Asset.ip_address.ilike(like)))
        .limit(limit)
    )).scalars().all()
    out["assets"] = [{"id": str(a.id), "title": a.name, "subtitle": f"{a.hostname or ''} {a.ip_address or ''}".strip(),
                      "badge": a.criticality.value.replace("_", " ")} for a in assets]

    risks = (await db.execute(select(Risk).where(Risk.title.ilike(like)).order_by(Risk.priority_score.desc()).limit(limit))).scalars().all()
    out["risks"] = [{"id": str(r.id), "title": r.title, "subtitle": r.status.value, "badge": f"BWVS {r.bwvs_score:.0f}"} for r in risks]

    incidents = (await db.execute(
        select(Incident).where(or_(Incident.title.ilike(like), Incident.ref.ilike(like))).limit(limit)
    )).scalars().all()
    out["incidents"] = [{"id": str(i.id), "title": f"{i.ref} {i.title}", "subtitle": i.status.value, "badge": i.severity.value} for i in incidents]

    if _IP.match(q):
        logs = (await db.execute(
            select(SecurityLog).where(or_(SecurityLog.source_ip.ilike(like), SecurityLog.destination_ip.ilike(like)))
            .order_by(SecurityLog.created_at.desc()).limit(limit)
        )).scalars().all()
        out["events"] = [{"id": str(l.id), "title": l.message[:90], "subtitle": f"{l.source_ip} -> {l.destination_ip}",
                          "badge": l.severity.value} for l in logs]
    return {"query": q, "results": out, "total": sum(len(v) for v in out.values())}
