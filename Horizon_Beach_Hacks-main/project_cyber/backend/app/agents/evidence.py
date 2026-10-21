"""
Contexta Backend - Evidence pack

The single source of truth handed to every agent. It is assembled from the
database (risk, CVE, asset, security events, digital twin, playbooks, history)
so agents reason over facts rather than free text.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import networkx as nx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.extras import AgentDiscussion
from app.models.incident import Incident
from app.models.log import SecurityLog
from app.models.risk import Risk
from app.risk_engine.ranking import risk_level
from app.services import settings_service, twin_service
from app.services.log_service import LogService
from app.services.playbook_service import PlaybookService
from app.services.risk_service import OPEN_STATUSES, RiskService

logger = structlog.get_logger()


def _plain(value: Any) -> Any:
    """Round-trip through JSON so the pack only contains plain types."""
    return json.loads(json.dumps(value, default=str))


def evidence_hash(evidence: Dict[str, Any]) -> str:
    body = {k: v for k, v in evidence.items() if k != "generated_at"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


async def build_evidence(
    db: AsyncSession,
    risk: Optional[Risk] = None,
    incident: Optional[Incident] = None,
) -> Dict[str, Any]:
    if risk is None and incident is None:
        raise ValueError("A risk or an incident is required")
    risks = RiskService(db)
    if risk is None and incident is not None and incident.risk_id:
        risk = await risks.get(incident.risk_id)

    evidence: Dict[str, Any] = {"generated_at": datetime.utcnow().isoformat()}
    evidence["organization"] = await settings_service.get_setting(db, "organization")
    asset = risk.asset if risk is not None else None

    if risk is not None:
        r = await risks.serialize(risk)
        evidence["risk"] = {
            k: r[k] for k in (
                "title", "description", "category", "source", "bwvs_score", "priority_score", "level", "status",
                "freshness_factor", "trend_factor", "ai_relevance_score", "first_seen", "last_seen",
                "affected_assets_count", "match_reasons", "components",
            )
        }
        evidence["risk"]["ai_relevance_basis"] = (r.get("ai_analysis") or {}).get("factors", [])
        evidence["cve"] = r.get("cve")
        if risk.cve is not None:
            evidence["cve"] = {
                **(r.get("cve") or {}),
                "attack_vector": risk.cve.attack_vector, "cvss_vector": risk.cve.cvss_vector,
                "cwes": risk.cve.cwes or [], "exploit_sources": risk.cve.exploit_sources or [],
                "kev_ransomware_use": bool(risk.cve.kev_ransomware_use),
                "epss_percentile": risk.cve.epss_percentile,
                "affected_software": (risk.cve.affected_software or [])[:10],
                "references": (risk.cve.references or [])[:5],
            }

    if incident is not None:
        evidence["incident"] = {
            "ref": incident.ref, "title": incident.title, "status": incident.status.value,
            "severity": incident.severity.value, "type": incident.incident_type, "assigned_to": incident.assigned_to,
            "opened": incident.created_at, "iocs": incident.iocs or {}, "notes": incident.notes,
            "timeline": (incident.timeline or [])[-12:],
        }

    if asset is not None:
        evidence["asset"] = {
            "name": asset.name, "hostname": asset.hostname, "ip_address": asset.ip_address,
            "type": asset.asset_type.value, "os": asset.os, "software": asset.software or [],
            "exposure": asset.exposure_level.value, "criticality": asset.criticality.value,
            "zone": asset.network_zone, "business_unit": asset.business_unit, "owner": asset.owner,
            "location": asset.location, "daily_revenue_impact_lakhs": asset.daily_revenue_impact,
            "is_isolated": bool(asset.is_isolated),
        }

        logs = await LogService(db).recent_for_asset(asset.id, limit=25)
        evidence["recent_events"] = [
            {
                "time": l.created_at, "category": l.category.value, "severity": l.severity.value,
                "message": l.message[:240], "source": l.source, "src_ip": l.source_ip, "dst_ip": l.destination_ip,
                "dst_port": l.destination_port, "user": l.username,
            }
            for l in logs
        ]
        since = datetime.utcnow() - timedelta(hours=24)
        counts: Dict[str, int] = {}
        for l in logs:
            if l.created_at >= since:
                key = f"{l.category.value}/{l.severity.value}"
                counts[key] = counts.get(key, 0) + 1
        evidence["event_stats_24h"] = counts
        ind: Dict[str, List[str]] = {"ips": [], "domains": [], "hashes": []}
        for l in logs:
            for key, bucket in (("ips", "ips"), ("domains", "domains"), ("file_hashes", "hashes"), ("hashes", "hashes")):
                for v in (l.indicators or {}).get(key, []) or []:
                    if v not in ind[bucket]:
                        ind[bucket].append(v)
        evidence["indicators"] = {k: v[:20] for k, v in ind.items() if v}

        evidence["network"] = await _network_context(db, str(asset.id))

        q = select(Risk).where(Risk.asset_id == asset.id, Risk.status.in_(OPEN_STATUSES))
        if risk is not None:
            q = q.where(Risk.id != risk.id)
        others = (await db.execute(q.order_by(Risk.bwvs_score.desc()).limit(8))).scalars().all()
        evidence["related_risks_same_asset"] = [
            {"title": o.title, "bwvs": o.bwvs_score, "level": risk_level(o.bwvs_score or 0)} for o in others
        ]
    else:
        evidence["recent_events"] = []

    if risk is not None and risk.cve_id:
        peers = (await db.execute(
            select(Risk).where(Risk.cve_id == risk.cve_id, Risk.status.in_(OPEN_STATUSES), Risk.id != risk.id).limit(8)
        )).scalars().all()
        evidence["same_cve_other_assets"] = [{"title": p.title, "bwvs": p.bwvs_score} for p in peers]

    if risk is not None:
        recs = await PlaybookService(db).recommend(risk, limit=3)
        evidence["playbooks"] = [
            {"slug": pb.slug, "name": pb.name, "score": score, "reasons": reasons,
             "steps": [s["name"] for s in (pb.steps or [])]}
            for pb, score, reasons in recs
        ]
        prev = (await db.execute(
            select(AgentDiscussion).where(AgentDiscussion.risk_id == risk.id, AgentDiscussion.status == "completed")
            .order_by(AgentDiscussion.created_at.desc()).limit(2)
        )).scalars().all()
        evidence["previous_assessments"] = [
            {"when": d.created_at, "consensus_severity": (d.consensus or {}).get("consensus_severity"),
             "summary": (d.consensus or {}).get("executive_summary", "")[:300]}
            for d in prev
        ]
    return _plain(evidence)


async def _network_context(db: AsyncSession, asset_id: str) -> Dict[str, Any]:
    twin, by_id = await twin_service.build_twin(db)
    if asset_id not in by_id:
        return {"note": "asset is isolated or inactive, so it is not part of the active network graph"}
    blast = twin.calculate_blast_radius(asset_id, max_hops=3)
    ctx: Dict[str, Any] = {
        "zone": by_id[asset_id].network_zone,
        "blast_radius_assets": blast.get("total_affected_assets", 0),
        "blast_by_criticality": blast.get("affected_by_criticality", {}),
        "critical_assets_reachable": [by_id[a].name for a in blast.get("critical_assets_at_risk", []) if a in by_id],
        "neighbors": [by_id[n].name for n in twin.graph.neighbors(asset_id) if n in by_id][:10],
        "paths_from_internet": [],
    }
    for entry in twin.entry_points():
        if entry == asset_id:
            ctx["paths_from_internet"].append([by_id[asset_id].name + " (directly exposed)"])
            continue
        try:
            path = nx.shortest_path(twin.graph, entry, asset_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        ctx["paths_from_internet"].append([by_id[n].name for n in path if n in by_id])
        if len(ctx["paths_from_internet"]) >= 3:
            break
    return ctx
