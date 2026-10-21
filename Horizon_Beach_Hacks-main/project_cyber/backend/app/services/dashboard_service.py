"""
Contexta Backend - Dashboard / executive / report aggregates

Everything here is computed from stored data. Where a figure depends on an
assumption (expected downtime, exploit probability) the assumption is returned
alongside it so the UI can show the methodology.
"""

from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models.asset import Asset, AssetCriticality, ExposureLevel
from app.models.extras import RiskSnapshot
from app.models.incident import Incident, IncidentSeverity
from app.models.log import SecurityLog
from app.models.risk import Risk, RiskStatus
from app.risk_engine.ranking import risk_level
from app.services.incident_service import ACTIVE_STATUSES
from app.services.playbook_service import PlaybookService
from app.services.risk_service import OPEN_STATUSES, RiskService, expected_loss

logger = structlog.get_logger()


async def _open_risks(db: AsyncSession) -> List[Risk]:
    rows = await db.execute(
        select(Risk).options(selectinload(Risk.cve), selectinload(Risk.asset)).where(Risk.status.in_(OPEN_STATUSES))
    )
    return list(rows.scalars().all())


def _top_mean(risks: List[Risk], n: int = 10) -> float:
    top = sorted(risks, key=lambda r: r.priority_score or 0, reverse=True)[:n]
    return round(sum(r.bwvs_score or 0 for r in top) / len(top), 1) if top else 0.0


async def _snapshot_before(db: AsyncSession, hours: int) -> Optional[RiskSnapshot]:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    return (
        await db.execute(
            select(RiskSnapshot).where(RiskSnapshot.captured_at <= cutoff).order_by(RiskSnapshot.captured_at.desc()).limit(1)
        )
    ).scalar_one_or_none()


def derive_threat_level(risks: List[Risk], critical_incidents: int) -> Dict[str, str]:
    crit = [r for r in risks if risk_level(r.bwvs_score or 0) == "critical"]
    if critical_incidents or any(r.cve and r.cve.cisa_kev for r in crit) or any(r.source == "log_correlation" for r in crit):
        return {"level": "CRITICAL", "reason": "active critical incident, KEV-listed or actively attacked critical risk"}
    if crit:
        return {"level": "HIGH", "reason": f"{len(crit)} critical risk(s) open"}
    if any(risk_level(r.bwvs_score or 0) == "high" for r in risks):
        return {"level": "ELEVATED", "reason": "high-severity risks open"}
    return {"level": "GUARDED" if risks else "LOW", "reason": "no high or critical risks open" if risks else "no open risks"}


async def overview(db: AsyncSession) -> Dict[str, Any]:
    risks = await _open_risks(db)
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in risks:
        levels[risk_level(r.bwvs_score or 0)] += 1
    score = _top_mean(risks)

    incidents = (await db.execute(select(Incident))).scalars().all()
    active = [i for i in incidents if i.status in ACTIVE_STATUSES]
    critical_incidents = sum(1 for i in active if i.severity == IncidentSeverity.CRITICAL)
    resolved = [i for i in incidents if i.resolved_at]
    mttr = round(sum((i.resolved_at - i.created_at).total_seconds() for i in resolved) / len(resolved) / 3600, 1) if resolved else None

    assets = (await db.execute(select(Asset).where(Asset.is_active == True))).scalars().all()  # noqa: E712
    crit_assets = [a for a in assets if a.criticality in (AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND)]
    at_risk_ids = {r.asset_id for r in risks if r.asset_id and risk_level(r.bwvs_score or 0) in ("critical", "high")}

    prev = await _snapshot_before(db, 24)
    delta = None
    if prev is not None:
        delta = {
            "open_risks": len(risks) - prev.open_total,
            "critical": levels["critical"] - prev.critical,
            "avg_bwvs": round((sum(r.bwvs_score or 0 for r in risks) / len(risks) if risks else 0) - prev.avg_bwvs, 1),
        }
    vuln_open = [r for r in risks if r.source != "log_correlation"]
    return {
        "overall_risk_score": score,
        "security_score": round(100 - score),
        "open_risks": len(risks),
        "risks_by_level": levels,
        "active_incidents": len(active),
        "critical_incidents": critical_incidents,
        "critical_assets": len(crit_assets),
        "critical_assets_at_risk": sum(1 for a in crit_assets if a.id in at_risk_ids),
        "mean_time_to_resolve_hours": mttr,
        "threat_level": derive_threat_level(risks, critical_incidents),
        "active_vulnerabilities": len(vuln_open),
        "critical_threats": levels["critical"],
        "kev_open": sum(1 for r in risks if r.cve and r.cve.cisa_kev),
        "delta_24h": delta,
        "has_data": bool(assets),
        "assets_total": len(assets),
        "generated_at": datetime.utcnow().isoformat(),
    }


async def risk_trend(db: AsyncSession, days: int = 30) -> Dict[str, Any]:
    since = datetime.utcnow() - timedelta(days=days)
    snaps = (
        await db.execute(select(RiskSnapshot).where(RiskSnapshot.captured_at >= since).order_by(RiskSnapshot.captured_at))
    ).scalars().all()
    if not snaps:
        return {"granularity": "none", "points": [], "note": "History accumulates as risk scoring runs."}
    span = snaps[-1].captured_at - snaps[0].captured_at
    hourly = span < timedelta(hours=48)
    buckets: Dict[str, RiskSnapshot] = {}
    for s in snaps:  # later snapshots overwrite: last of the bucket wins
        key = s.captured_at.strftime("%Y-%m-%d %H:00" if hourly else "%Y-%m-%d")
        buckets[key] = s
    points = [
        {"bucket": k, "label": k[11:] if hourly else k[5:], "critical": s.critical, "high": s.high,
         "medium": s.medium, "low": s.low, "open_total": s.open_total, "avg_bwvs": s.avg_bwvs,
         "exposure_lakhs": s.exposure_lakhs}
        for k, s in sorted(buckets.items())
    ]
    return {"granularity": "hour" if hourly else "day", "points": points, "note": None}


async def departments(db: AsyncSession) -> List[Dict[str, Any]]:
    risks = await _open_risks(db)
    assets = (await db.execute(select(Asset).where(Asset.is_active == True))).scalars().all()  # noqa: E712
    incidents = [i for i in (await db.execute(select(Incident))).scalars().all() if i.status in ACTIVE_STATUSES]
    unit_of = {str(a.id): (a.business_unit or "Unassigned") for a in assets}
    stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"assets": 0, "scores": [], "incidents": 0})
    for a in assets:
        stats[a.business_unit or "Unassigned"]["assets"] += 1
    for r in risks:
        if r.asset_id:
            stats[unit_of.get(str(r.asset_id), "Unassigned")]["scores"].append(r.bwvs_score or 0)
    for i in incidents:
        for aid in i.affected_assets or []:
            if aid in unit_of:
                stats[unit_of[aid]]["incidents"] += 1
    out = []
    for unit, s in stats.items():
        scores = s["scores"]
        mx = max(scores) if scores else 0.0
        avg = sum(scores) / len(scores) if scores else 0.0
        out.append({
            "name": unit, "assets": s["assets"], "open_risks": len(scores), "incidents": s["incidents"],
            "max_bwvs": round(mx, 1), "avg_bwvs": round(avg, 1),
            "risk": round(0.6 * mx + 0.4 * avg), "level": risk_level(mx) if scores else "none",
        })
    out.sort(key=lambda d: d["risk"], reverse=True)
    return out


async def vulnerability_distribution(db: AsyncSession) -> List[Dict[str, Any]]:
    risks = await _open_risks(db)
    table: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for r in risks:
        key = r.asset.asset_type.value.replace("_", " ").title() if r.asset else "Unmapped"
        table[key][risk_level(r.bwvs_score or 0)] += 1
    rows = [{"category": k, **v, "total": sum(v.values())} for k, v in table.items()]
    rows.sort(key=lambda x: x["total"], reverse=True)
    return rows


async def recommended_actions(db: AsyncSession, limit: int = 6) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    # Critical active incidents without a running playbook
    incidents = [i for i in (await db.execute(select(Incident).options(selectinload(Incident.risk)))).scalars().all()
                 if i.status in ACTIVE_STATUSES and i.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH)]
    for i in incidents[:3]:
        actions.append({
            "kind": "incident", "priority": i.severity.value, "label": f"Respond to {i.ref}: {i.title}",
            "incident_id": str(i.id), "risk_id": str(i.risk_id) if i.risk_id else None,
        })
    svc = PlaybookService(db)
    risks = await RiskService(db).top(limit=limit)
    for r in risks:
        recs = await svc.recommend(r, limit=1)
        pb = recs[0][0] if recs else None
        reason = []
        if r.cve and r.cve.cisa_kev:
            reason.append("actively exploited (CISA KEV)")
        if r.source == "log_correlation":
            reason.append("live attack activity")
        if r.asset and r.asset.exposure_level == ExposureLevel.INTERNET_FACING:
            reason.append("internet-facing asset")
        actions.append({
            "kind": "risk", "priority": risk_level(r.bwvs_score or 0),
            "label": (f"Run '{pb.name}' for {r.title}" if pb else f"Remediate {r.title}"),
            "risk_id": str(r.id), "playbook_slug": pb.slug if pb else None,
            "reason": ", ".join(reason) or f"BWVS {r.bwvs_score:.0f}",
        })
    return actions[:limit]


async def executive(db: AsyncSession) -> Dict[str, Any]:
    risks = await _open_risks(db)
    loss = expected_loss(risks)
    by_unit: Dict[str, float] = defaultdict(float)
    for item in loss["by_asset"]:
        by_unit[item["business_unit"] or "Unassigned"] += item["expected_loss_lakhs"]
    by_category: Dict[str, float] = defaultdict(float)
    for r in risks:
        if r.asset_id:
            share = next((i["expected_loss_lakhs"] for i in loss["by_asset"] if i["asset_id"] == str(r.asset_id)), 0)
            by_category[r.category or "vulnerability"] += share / max(1, sum(1 for x in risks if x.asset_id == r.asset_id))

    score = _top_mean(risks)
    now = datetime.utcnow()
    sla = settings.critical_risk_sla_days
    breaches = [r for r in risks if risk_level(r.bwvs_score or 0) == "critical" and (now - r.first_seen).days >= sla]
    internet_exposed = {r.asset_id for r in risks if r.asset and r.asset.exposure_level == ExposureLevel.INTERNET_FACING
                        and risk_level(r.bwvs_score or 0) in ("critical", "high")}
    all_risks = (await db.execute(select(Risk))).scalars().all()
    month_ago = now - timedelta(days=30)
    opened = sum(1 for r in all_risks if r.first_seen >= month_ago)
    closed = sum(1 for r in all_risks if r.resolved_at and r.resolved_at >= month_ago)
    resolved_times = [(r.resolved_at - r.first_seen).total_seconds() / 86400 for r in all_risks if r.resolved_at]

    prev = await _snapshot_before(db, 24 * 7)
    trend_label, trend_delta = "Stable", 0.0
    if prev is not None:
        cur_avg = sum(r.bwvs_score or 0 for r in risks) / len(risks) if risks else 0.0
        trend_delta = round(cur_avg - prev.avg_bwvs, 1)
        trend_label = "Rising" if trend_delta > 1 else "Falling" if trend_delta < -1 else "Stable"

    monthly = await db.execute(select(RiskSnapshot).where(RiskSnapshot.captured_at >= now - timedelta(days=190)).order_by(RiskSnapshot.captured_at))
    by_month: Dict[str, List[RiskSnapshot]] = defaultdict(list)
    for s in monthly.scalars().all():
        by_month[s.captured_at.strftime("%Y-%m")].append(s)
    monthly_scores = [
        {"month": m, "risk_score_10": round(sum(x.avg_bwvs for x in v) / len(v) / 10, 1),
         "exposure_lakhs": round(sum(x.exposure_lakhs for x in v) / len(v), 1)}
        for m, v in sorted(by_month.items())
    ]
    return {
        "business_risk_score": round(score / 10, 1),
        "financial_exposure_lakhs": loss["total_lakhs"],
        "exposure_by_business_unit": [{"name": k, "lakhs": round(v, 2)} for k, v in sorted(by_unit.items(), key=lambda kv: -kv[1])],
        "top_exposed_assets": loss["by_asset"][:6],
        "exposure_by_category": [{"name": k, "lakhs": round(v, 2)} for k, v in sorted(by_category.items(), key=lambda kv: -kv[1])],
        "risk_trend": {"label": trend_label, "delta_7d": trend_delta},
        "control_health": {
            "kev_open": sum(1 for r in risks if r.cve and r.cve.cisa_kev),
            "internet_facing_assets_with_serious_risk": len(internet_exposed),
            "critical_sla_days": sla,
            "critical_sla_breaches": len(breaches),
            "risks_opened_30d": opened,
            "risks_resolved_30d": closed,
            "mean_days_to_resolve": round(sum(resolved_times) / len(resolved_times), 1) if resolved_times else None,
        },
        "monthly_trend": monthly_scores,
        "assumptions": [
            f"Downtime assumed {settings.expected_downtime_days_critical:g} day(s) for payment/core assets, "
            f"{settings.expected_downtime_days_default:g} day(s) otherwise",
            "Exploit probability: EPSS where available, at least 50% for CISA KEV, otherwise a CVSS-scaled prior, "
            "scaled by asset exposure; combined per asset as 1 - prod(1 - p)",
            "Revenue impact per asset is taken from the asset inventory (INR lakhs/day)",
        ],
        "currency": "INR lakhs",
        "generated_at": now.isoformat(),
    }


def _month_keys(n: int) -> List[str]:
    today = date.today().replace(day=1)
    keys = []
    for i in range(n - 1, -1, -1):
        y, m = today.year, today.month - i
        while m <= 0:
            y, m = y - 1, m + 12
        keys.append(f"{y}-{m:02d}")
    return keys


async def reports(db: AsyncSession, months: int = 6, weeks: int = 6) -> Dict[str, Any]:
    keys = _month_keys(months)
    incidents = (await db.execute(select(Incident))).scalars().all()
    monthly = {k: {"month": k, "incidents": 0, "resolved": 0, "pending": 0} for k in keys}
    for i in incidents:
        k = i.created_at.strftime("%Y-%m")
        if k in monthly:
            monthly[k]["incidents"] += 1
            if i.resolved_at:
                monthly[k]["resolved"] += 1
            else:
                monthly[k]["pending"] += 1

    since = datetime.utcnow() - timedelta(weeks=weeks)
    rows = (
        await db.execute(
            select(func.date(SecurityLog.created_at), SecurityLog.category, func.count(SecurityLog.id))
            .where(SecurityLog.created_at >= since).group_by(func.date(SecurityLog.created_at), SecurityLog.category)
        )
    ).all()
    weekly: Dict[str, Dict[str, int]] = {}
    today = date.today()
    for w in range(weeks - 1, -1, -1):
        start = today - timedelta(days=today.weekday()) - timedelta(weeks=w)
        weekly[start.isoformat()] = {}
    for d, cat, n in rows:
        day = d if isinstance(d, date) else date.fromisoformat(str(d)[:10])
        start = (day - timedelta(days=day.weekday())).isoformat()
        if start in weekly:
            c = cat.value if hasattr(cat, "value") else str(cat)
            weekly[start][c] = weekly[start].get(c, 0) + n
    threat_activity = [{"week": k, **v} for k, v in weekly.items()]

    risks = await _open_risks(db)
    all_risks = (await db.execute(select(Risk))).scalars().all()
    resolved_incidents = [i for i in incidents if i.resolved_at]
    return {
        "kpis": {
            "incidents_total": len(incidents),
            "incidents_resolved_pct": round(100 * len(resolved_incidents) / len(incidents)) if incidents else None,
            "mean_time_to_resolve_hours": round(sum((i.resolved_at - i.created_at).total_seconds() for i in resolved_incidents) / len(resolved_incidents) / 3600, 1) if resolved_incidents else None,
            "open_risks": len(risks),
            "critical_risks": sum(1 for r in risks if risk_level(r.bwvs_score or 0) == "critical"),
            "risks_resolved": sum(1 for r in all_risks if r.status == RiskStatus.RESOLVED),
            "events_processed": (await db.execute(select(func.count(SecurityLog.id)))).scalar() or 0,
            "average_bwvs": round(sum(r.bwvs_score or 0 for r in risks) / len(risks), 1) if risks else 0,
        },
        "monthly_incidents": list(monthly.values()),
        "vulnerability_distribution": await vulnerability_distribution(db),
        "threat_activity": threat_activity,
        "top_risks": [
            {"title": r.title, "bwvs": r.bwvs_score, "priority": r.priority_score, "level": risk_level(r.bwvs_score or 0),
             "asset": r.asset.name if r.asset else None, "cve": r.cve.cve_id if r.cve else None}
            for r in sorted(risks, key=lambda r: r.priority_score or 0, reverse=True)[:10]
        ],
        "generated_at": datetime.utcnow().isoformat(),
    }
