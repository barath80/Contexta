"""
Contexta Backend - Digital Twin Service

Builds the NetworkX digital twin from the real asset inventory, the stored
connections and the open vulnerability risks, then runs attack simulations.
"""

import uuid
from typing import Any, Dict, List, Optional, Tuple

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.asset import Asset, AssetCriticality
from app.models.extras import AssetConnection
from app.models.risk import Risk, RiskStatus
from app.risk_engine.ranking import risk_level
from app.twin.engine import DigitalTwinEngine

logger = structlog.get_logger()

TWIN_CRITICALITY = {
    AssetCriticality.PAYMENT_PAYROLL: "critical",
    AssetCriticality.CORE_BACKEND: "high",
    AssetCriticality.CRM_HR: "medium",
    AssetCriticality.DEV_TEST: "low",
}
OPEN = (RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)

# Attack model assumptions (documented in the API response as well).
ATTACKS: Dict[str, Dict[str, Any]] = {
    "ransomware": {
        "label": "Ransomware", "max_hops": 4, "propagation": 0.5, "steps": 10, "spreads": True,
        "downtime_days": 5.0, "time_to_impact": "Hours",
        "method": "Network propagation via shares and remote services",
        "tactics": [("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
                    ("TA0005", "Defense Evasion"), ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"),
                    ("TA0009", "Collection"), ("TA0040", "Impact")],
    },
    "apt": {
        "label": "APT / targeted intrusion", "max_hops": 6, "propagation": 0.25, "steps": 15, "spreads": True,
        "downtime_days": 3.0, "time_to_impact": "Days to weeks",
        "method": "Targeted lateral movement with persistence and credential theft",
        "tactics": [("TA0001", "Initial Access"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
                    ("TA0006", "Credential Access"), ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"),
                    ("TA0009", "Collection"), ("TA0010", "Exfiltration")],
    },
    "insider": {
        "label": "Insider threat", "max_hops": 2, "propagation": 0.0, "steps": 1, "spreads": False,
        "downtime_days": 1.0, "time_to_impact": "Immediate",
        "method": "Direct abuse of authorised access to data stores",
        "tactics": [("TA0006", "Credential Access"), ("TA0009", "Collection"), ("TA0010", "Exfiltration")],
    },
    "ddos": {
        "label": "Denial of service", "max_hops": 1, "propagation": 0.0, "steps": 1, "spreads": False,
        "downtime_days": 0.5, "time_to_impact": "Seconds to minutes",
        "method": "Saturating internet-facing services",
        "tactics": [("TA0040", "Impact")],
    },
}

MITIGATIONS = {
    "ransomware": ["Segment the network between zones", "Maintain offline, immutable backups and test restores",
                   "Disable legacy SMB and restrict lateral remote-service access", "Deploy EDR with ransomware behaviour rules"],
    "apt": ["Enforce least-privilege and tiered admin accounts", "Enable MFA on every remote access path",
            "Hunt for persistence on assets along the path", "Forward authentication logs to the SIEM for correlation"],
    "insider": ["Apply least-privilege access to data stores", "Deploy DLP and database activity monitoring",
                "Review privileged access quarterly", "Alert on bulk reads / unusual export volumes"],
    "ddos": ["Front internet-facing services with a CDN/WAF and rate limiting", "Provision upstream scrubbing",
             "Autoscale stateless tiers", "Define a DDoS runbook with the ISP"],
}


async def build_twin(db: AsyncSession) -> Tuple[DigitalTwinEngine, Dict[str, Asset]]:
    """Construct a twin from the database. Node ids are asset UUID strings."""
    twin = DigitalTwinEngine()
    assets = (await db.execute(select(Asset).where(Asset.is_active == True))).scalars().all()  # noqa: E712
    by_id: Dict[str, Asset] = {}
    for a in assets:
        sid = str(a.id)
        by_id[sid] = a
        twin.add_asset(
            asset_id=sid, asset_type=a.asset_type.value, name=a.name,
            criticality=TWIN_CRITICALITY.get(a.criticality, "medium"), zone=a.network_zone or "internal",
            metadata={"exposure": a.exposure_level.value, "isolated": bool(a.is_isolated)},
        )
    for c in (await db.execute(select(AssetConnection))).scalars().all():
        s, t = str(c.source_asset_id), str(c.target_asset_id)
        if s not in by_id or t not in by_id:
            continue
        if by_id[s].is_isolated or by_id[t].is_isolated:
            continue  # isolated assets are cut off from the network
        twin.add_connection(s, t, c.connection_type, c.protocols or ["tcp"], bidirectional=bool(c.bidirectional))
    risks = (
        await db.execute(
            select(Risk).options(selectinload(Risk.cve)).where(Risk.status.in_(OPEN), Risk.cve_id != None)  # noqa: E711
        )
    ).scalars().all()
    for r in risks:
        if str(r.asset_id) in by_id and r.cve:
            twin.add_vulnerability(
                str(r.asset_id), r.cve.cve_id, r.cve.cvss_score or 0.0,
                exploitable=bool(r.cve.has_exploit),
                network_exploitable=(r.cve.attack_vector or "").upper() == "NETWORK",
            )
    return twin, by_id


def _label(by_id: Dict[str, Asset], aid: str) -> str:
    a = by_id.get(aid)
    return a.name if a else aid


def _asset_brief(a: Asset) -> Dict[str, Any]:
    return {
        "id": str(a.id), "name": a.name, "asset_type": a.asset_type.value,
        "criticality": a.criticality.value, "zone": a.network_zone,
        "daily_revenue_impact_lakhs": a.daily_revenue_impact or 0.0,
    }


async def topology(db: AsyncSession) -> Dict[str, Any]:
    twin, by_id = await build_twin(db)
    risks = (
        await db.execute(select(Risk.asset_id, Risk.bwvs_score).where(Risk.status.in_(OPEN)))
    ).all()
    worst: Dict[str, float] = {}
    count: Dict[str, int] = {}
    for aid, bwvs in risks:
        k = str(aid)
        worst[k] = max(worst.get(k, 0.0), bwvs or 0.0)
        count[k] = count.get(k, 0) + 1
    nodes = []
    for sid, a in by_id.items():
        nodes.append({
            "id": sid, "name": a.name, "asset_type": a.asset_type.value, "zone": a.network_zone,
            "criticality": a.criticality.value, "exposure": a.exposure_level.value,
            "is_isolated": bool(a.is_isolated), "open_risks": count.get(sid, 0),
            "max_bwvs": round(worst.get(sid, 0.0), 1),
            "risk_level": risk_level(worst[sid]) if sid in worst else "none",
        })
    edges = [
        {"source": u, "target": v, "type": d.get("type", "network"), "protocols": d.get("protocols", [])}
        for u, v, d in twin.graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges, "stats": twin.get_network_stats(), "entry_points": twin.entry_points()}


async def critical_paths(db: AsyncSession) -> List[Dict[str, Any]]:
    twin, by_id = await build_twin(db)
    out = []
    for p in twin.find_critical_paths():
        out.append({**p, "path_names": [_label(by_id, n) for n in p["path"]],
                    "entry_name": _label(by_id, p["entry_point"]), "target_name": _label(by_id, p["target"])})
    return out


async def blast_radius(db: AsyncSession, asset_id: str, max_hops: int = 3) -> Optional[Dict[str, Any]]:
    twin, by_id = await build_twin(db)
    if asset_id not in by_id:
        return None
    res = twin.calculate_blast_radius(asset_id, max_hops=max_hops)
    res["source_name"] = _label(by_id, asset_id)
    for key in ("critical_assets_at_risk", "high_assets_at_risk"):
        res[key] = [{"id": a, "name": _label(by_id, a)} for a in res.get(key, [])]
    return res


async def attack_paths(db: AsyncSession, start_id: str, target_id: str, algorithm: str = "bfs", max_depth: int = 8):
    twin, by_id = await build_twin(db)
    if start_id not in by_id or target_id not in by_id:
        return None
    fn = twin.find_attack_paths_dfs if algorithm == "dfs" else twin.find_attack_paths_bfs
    paths = fn(start_id, target_id, max_depth=max_depth)
    paths.sort(key=len)
    return [
        {"path": p, "path_names": [_label(by_id, n) for n in p], "hops": len(p) - 1,
         "risk_score": twin._calculate_path_risk(p)}
        for p in paths[:50]
    ]


async def simulate(
    db: AsyncSession,
    attack_type: str,
    entry_point: Optional[str] = None,
    target: Optional[str] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    attack_type = attack_type.lower()
    cfg = ATTACKS.get(attack_type)
    if cfg is None:
        raise ValueError(f"Unknown attack type '{attack_type}'. Choose from: {', '.join(ATTACKS)}")
    twin, by_id = await build_twin(db)
    if not by_id:
        raise ValueError("The asset inventory is empty. Add assets before running a simulation.")

    entries = twin.entry_points()
    if entry_point:
        if entry_point not in by_id:
            raise ValueError("Entry point asset not found or inactive")
    elif entries:
        entry_point = max(entries, key=lambda a: by_id[a].exposure_score * 10 + by_id[a].criticality_score)
    else:
        entry_point = next(iter(by_id))
    if target and target not in by_id:
        raise ValueError("Target asset not found or inactive")

    if attack_type == "ddos":
        targets = [a for a in entries] or [entry_point]
    elif attack_type == "insider":
        targets = [k for k, a in by_id.items() if a.asset_type.value in ("database", "server", "application")
                   and a.criticality in (AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND)]
    else:
        targets = [k for k, a in by_id.items() if a.criticality == AssetCriticality.PAYMENT_PAYROLL] or \
                  [k for k, a in by_id.items() if a.criticality == AssetCriticality.CORE_BACKEND]
    if target:
        targets = [target]

    paths_found: List[Dict[str, Any]] = []
    for t in targets:
        if t == entry_point:
            continue
        for p in sorted(twin.find_attack_paths_bfs(entry_point, t, max_depth=cfg["max_hops"] + 1), key=len)[:3]:
            paths_found.append({
                "path": p, "path_names": [_label(by_id, n) for n in p], "hops": len(p) - 1,
                "risk_score": min(10.0, twin._calculate_path_risk(p)),
                "target": t, "target_name": _label(by_id, t),
                "description": f"{len(p) - 1}-hop path from {_label(by_id, p[0])} to {_label(by_id, p[-1])}",
                "mitigations": MITIGATIONS[attack_type][:3],
            })
    paths_found.sort(key=lambda x: x["risk_score"], reverse=True)

    blast = twin.calculate_blast_radius(entry_point, max_hops=cfg["max_hops"])
    reachable = set()
    frontier = {entry_point}
    for _ in range(cfg["max_hops"]):
        nxt = set()
        for n in frontier:
            nxt.update(twin.graph.neighbors(n))
        reachable |= nxt
        frontier = nxt - reachable
    reachable.discard(entry_point)

    timeline: List[Dict[str, Any]] = []
    if cfg["spreads"]:
        sim = twin.simulate_lateral_movement(entry_point, cfg["steps"], cfg["propagation"], seed=seed)
        compromised = set(sim["compromised_assets"])
        timeline = [
            {"step": t["time_step"], "newly_compromised": [_label(by_id, n) for n in t["newly_compromised"]],
             "total": t["total_compromised"]}
            for t in sim["timeline"]
        ]
    elif attack_type == "ddos":
        compromised = {entry_point} | set(entries)
    else:  # insider: direct access to the data stores reachable in <=2 hops
        compromised = {entry_point} | {n for n in reachable if n in set(targets)}

    affected = [by_id[n] for n in compromised if n in by_id]
    daily = sum(a.daily_revenue_impact or 0 for a in affected)
    critical_hit = [a for a in affected if a.criticality == AssetCriticality.PAYMENT_PAYROLL]
    loss = round(daily * cfg["downtime_days"], 2)

    total = max(1, len(by_id))
    share = len(compromised) / total
    if critical_hit and (share > 0.3 or attack_type in ("apt", "insider")):
        level = "CRITICAL"
    elif critical_hit or share > 0.3:
        level = "HIGH"
    elif share > 0.1 or paths_found:
        level = "MEDIUM"
    else:
        level = "LOW"

    tactics = []
    for tid, name in cfg["tactics"]:
        active = not (name in ("Lateral Movement", "Privilege Escalation") and not paths_found)
        tactics.append({"id": tid, "name": name, "active": active})

    return {
        "simulation_id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "attack_label": cfg["label"],
        "entry_point": entry_point,
        "entry_point_name": _label(by_id, entry_point),
        "target": target,
        "paths_found": paths_found[:10],
        "blast_radius": [{"id": n, "name": _label(by_id, n)} for n in sorted(reachable)],
        "compromised_assets": [_brief for _brief in map(_asset_brief, affected)],
        "critical_assets_compromised": [_asset_brief(a) for a in critical_hit],
        "timeline": timeline,
        "risk_assessment": level,
        "impact": {
            "assets_compromised": len(compromised),
            "assets_total": total,
            "daily_revenue_at_risk_lakhs": round(daily, 2),
            "estimated_downtime_days": cfg["downtime_days"],
            "estimated_loss_lakhs": loss,
            "time_to_impact": cfg["time_to_impact"],
            "primary_method": cfg["method"],
            "blast_risk_score": blast.get("risk_score", 0),
        },
        "tactics": tactics,
        "recommendations": MITIGATIONS[attack_type],
        "assumptions": [
            f"Downtime of {cfg['downtime_days']:g} day(s) for a {cfg['label'].lower()} scenario",
            "Loss = sum of daily revenue impact of compromised assets x downtime",
            f"Per-step propagation probability {cfg['propagation']}" if cfg["spreads"] else "No lateral propagation modelled",
        ],
    }
