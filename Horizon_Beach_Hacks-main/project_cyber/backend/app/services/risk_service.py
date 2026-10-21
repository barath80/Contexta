"""
Contexta Backend - Risk Service

Creates, scores and ranks risks.

* CVE <-> asset correlation uses real software matching (no guessing).
* BWVS follows the documented formula; AI relevance comes from Gemini when an
  agent discussion/assessment has run, otherwise from a transparent heuristic.
* Priority = BWVS x Freshness x TrendFactor.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models.asset import Asset, AssetCriticality, ExposureLevel
from app.models.cve import CVE
from app.models.log import LogSeverity, SecurityLog
from app.models.risk import Risk, RiskScore, RiskStatus
from app.risk_engine.bwvs import BWVSCalculator
from app.risk_engine.ranking import (
    calculate_freshness, calculate_priority, calculate_trend_factor, risk_level,
)
from app.services import settings_service
from app.services.software_matcher import match_asset_versioned

logger = structlog.get_logger()

OPEN_STATUSES = (RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)
MIN_MATCH_SCORE = 70

# CVSS-equivalent used for threats observed in logs (no CVE exists).
LOG_SEVERITY_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}

# Probability weighting by exposure when estimating expected loss.
EXPOSURE_P = {
    ExposureLevel.INTERNET_FACING: 1.0,
    ExposureLevel.VPN: 0.7,
    ExposureLevel.INTERNAL: 0.4,
    ExposureLevel.ISOLATED: 0.1,
}


def heuristic_relevance(cve: Optional[CVE], asset: Optional[Asset], match_score: int = 0) -> Tuple[float, List[str]]:
    """Transparent relevance estimate (0-100) used when no AI assessment exists."""
    factors: List[str] = []
    pct = 40.0
    if match_score:
        pct += (match_score - MIN_MATCH_SCORE) * 0.5
        factors.append(f"software match score {match_score}")
    if cve is not None:
        if cve.cisa_kev:
            pct += 20
            factors.append("listed in CISA KEV")
        elif cve.has_exploit:
            pct += 10
            factors.append("public exploit available")
        if cve.epss_score:
            pct += 20 * cve.epss_score
            factors.append(f"EPSS {cve.epss_score:.2f}")
        remote = (cve.attack_vector or "").upper() == "NETWORK"
        if asset is not None:
            reachable = asset.exposure_level in (ExposureLevel.INTERNET_FACING, ExposureLevel.VPN)
            if remote and reachable:
                pct += 15
                factors.append("network-exploitable on reachable asset")
            elif (cve.attack_vector or "").upper() in ("LOCAL", "PHYSICAL") and \
                    asset.exposure_level == ExposureLevel.INTERNET_FACING:
                pct -= 10
                factors.append("local-only vector")
    return max(5.0, min(98.0, round(pct, 1))), factors


def exploit_probability(*, epss: Optional[float], kev: bool, cvss: float, from_logs: bool, exposure: str) -> float:
    """
    Probability that a risk is exploited: EPSS when known, else a CVSS-scaled
    prior; at least 0.5 for CISA KEV; 0.6 for threats observed in logs; scaled
    by how reachable the asset is.
    """
    if epss is not None:
        p = epss
    elif cvss:
        p = 0.02 + 0.08 * cvss / 10
    else:
        p = 0.6 if from_logs else 0.1
    if kev:
        p = max(p, 0.5)
    if from_logs:
        p = max(p, 0.6)
    scale = EXPOSURE_P.get(ExposureLevel(exposure), 0.4)
    return min(0.99, p * scale)


def expected_loss(risks: Iterable[Risk]) -> Dict[str, Any]:
    """
    Expected financial loss (INR lakhs) for a set of open risks.

    Per asset: P(compromise) = 1 - prod(1 - p_i), where p_i is the probability
    of exploitation of risk i (EPSS when known; at least 0.5 for CISA KEV;
    0.6 for threats observed in logs; otherwise a CVSS-scaled prior), scaled
    by exposure. Loss = daily_revenue_impact x expected_downtime x P.
    """
    by_asset: Dict[UUID, Dict[str, Any]] = {}
    for r in risks:
        a = r.asset
        if a is None:
            continue
        cve = r.cve
        p = exploit_probability(
            epss=cve.epss_score if cve else None, kev=bool(cve and cve.cisa_kev),
            cvss=(cve.cvss_score or 0) if cve else 0.0, from_logs=(cve is None and r.source == "log_correlation"),
            exposure=a.exposure_level.value,
        )
        slot = by_asset.setdefault(a.id, {"asset": a, "survive": 1.0, "risks": 0})
        slot["survive"] *= 1 - p
        slot["risks"] += 1

    items = []
    total = 0.0
    for slot in by_asset.values():
        a: Asset = slot["asset"]
        days = (
            settings.expected_downtime_days_critical
            if a.criticality in (AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND)
            else settings.expected_downtime_days_default
        )
        prob = 1 - slot["survive"]
        loss = (a.daily_revenue_impact or 0.0) * days * prob
        total += loss
        items.append({
            "asset_id": str(a.id), "asset_name": a.name, "business_unit": a.business_unit,
            "probability": round(prob, 3), "downtime_days": days,
            "daily_revenue_impact_lakhs": a.daily_revenue_impact or 0.0,
            "expected_loss_lakhs": round(loss, 2), "open_risks": slot["risks"],
        })
    items.sort(key=lambda i: i["expected_loss_lakhs"], reverse=True)
    return {"total_lakhs": round(total, 2), "by_asset": items}


class RiskService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.calculator = BWVSCalculator()

    # ------------------------------------------------------------------ query
    def _base_query(self):
        return select(Risk).options(selectinload(Risk.cve), selectinload(Risk.asset))

    async def get(self, risk_id: str | UUID) -> Optional[Risk]:
        try:
            rid = risk_id if isinstance(risk_id, UUID) else UUID(str(risk_id))
        except ValueError:
            return None
        return (await self.db.execute(self._base_query().where(Risk.id == rid))).scalar_one_or_none()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        status: Optional[RiskStatus] = None,
        min_bwvs: Optional[float] = None,
        level: Optional[str] = None,
        category: Optional[str] = None,
        asset_id: Optional[UUID] = None,
        q: Optional[str] = None,
        open_only: bool = False,
    ) -> Tuple[List[Risk], int]:
        query = self._base_query()
        count_q = select(func.count(Risk.id))
        conds = []
        if status:
            conds.append(Risk.status == status)
        elif open_only:
            conds.append(Risk.status.in_(OPEN_STATUSES))
        if min_bwvs is not None:
            conds.append(Risk.bwvs_score >= min_bwvs)
        if level:
            lo, hi = {"critical": (80, 101), "high": (60, 80), "medium": (40, 60), "low": (0, 40)}[level]
            conds.append(and_(Risk.bwvs_score >= lo, Risk.bwvs_score < hi))
        if category:
            conds.append(Risk.category == category)
        if asset_id:
            conds.append(Risk.asset_id == asset_id)
        if q:
            conds.append(Risk.title.ilike(f"%{q}%"))
        for c in conds:
            query = query.where(c)
            count_q = count_q.where(c)
        total = (await self.db.execute(count_q)).scalar() or 0
        rows = (
            await self.db.execute(
                query.order_by(Risk.priority_score.desc(), Risk.bwvs_score.desc())
                .offset((page - 1) * page_size).limit(page_size)
            )
        ).scalars().all()
        return list(rows), total

    async def top(self, limit: int = 10) -> List[Risk]:
        rows = await self.db.execute(
            self._base_query().where(Risk.status.in_(OPEN_STATUSES))
            .order_by(Risk.priority_score.desc(), Risk.bwvs_score.desc()).limit(limit)
        )
        return list(rows.scalars().all())

    async def serialize_many(self, risks: List[Risk]) -> List[Dict[str, Any]]:
        if not risks:
            return []
        ids = [r.id for r in risks]
        comps = await self._latest_components(ids)
        cve_ids = [r.cve_id for r in risks if r.cve_id]
        counts: Dict[UUID, int] = {}
        if cve_ids:
            rows = await self.db.execute(
                select(Risk.cve_id, func.count(func.distinct(Risk.asset_id)))
                .where(Risk.cve_id.in_(cve_ids), Risk.status.in_(OPEN_STATUSES))
                .group_by(Risk.cve_id)
            )
            counts = {cid: n for cid, n in rows.all()}
        return [self._serialize(r, comps.get(r.id), counts.get(r.cve_id, 1) if r.cve_id else 1) for r in risks]

    async def serialize(self, risk: Risk) -> Dict[str, Any]:
        return (await self.serialize_many([risk]))[0]

    def _serialize(self, r: Risk, comp: Optional[RiskScore], affected: int) -> Dict[str, Any]:
        cve = r.cve
        asset = r.asset
        return {
            "id": r.id, "title": r.title, "description": r.description,
            "category": r.category or "vulnerability", "source": r.source or "cve_correlation",
            "bwvs_score": round(r.bwvs_score or 0, 2), "priority_score": round(r.priority_score or 0, 2),
            "level": risk_level(r.bwvs_score or 0), "status": r.status,
            "ai_relevance_score": r.ai_relevance_score or 0, "ai_analysis": r.ai_analysis or {},
            "freshness_factor": r.freshness_factor, "trend_factor": r.trend_factor,
            "first_seen": r.first_seen, "last_seen": r.last_seen, "resolved_at": r.resolved_at,
            "is_top_10": bool(r.is_top_10), "remediation_notes": r.remediation_notes,
            "match_reasons": r.match_reasons or [], "affected_assets_count": max(1, affected),
            "cve": None if cve is None else {
                "id": cve.id, "cve_id": cve.cve_id, "cvss_score": cve.cvss_score or 0,
                "severity": cve.severity, "cisa_kev": bool(cve.cisa_kev), "has_exploit": bool(cve.has_exploit),
                "epss_score": cve.epss_score, "description": cve.description or "",
                "published_date": cve.published_date,
            },
            "asset": None if asset is None else {
                "id": asset.id, "name": asset.name, "hostname": asset.hostname, "ip_address": asset.ip_address,
                "asset_type": asset.asset_type.value, "exposure_level": asset.exposure_level.value,
                "criticality": asset.criticality.value, "business_unit": asset.business_unit,
                "is_isolated": bool(asset.is_isolated),
            },
            "components": None if comp is None else {
                "cvss_score": comp.cvss_score, "exploit_activity": comp.exploit_activity,
                "exposure_level": comp.exposure_level, "asset_criticality": comp.asset_criticality,
                "business_impact": comp.business_impact, "ai_relevance": comp.ai_relevance,
                "final_bwvs": comp.final_bwvs,
            },
            "created_at": r.created_at, "updated_at": r.updated_at,
        }

    async def _latest_components(self, risk_ids: List[UUID]) -> Dict[UUID, RiskScore]:
        sub = (
            select(RiskScore.risk_id, func.max(RiskScore.calculation_timestamp).label("ts"))
            .where(RiskScore.risk_id.in_(risk_ids)).group_by(RiskScore.risk_id).subquery()
        )
        rows = await self.db.execute(
            select(RiskScore).join(
                sub, and_(RiskScore.risk_id == sub.c.risk_id, RiskScore.calculation_timestamp == sub.c.ts)
            )
        )
        return {s.risk_id: s for s in rows.scalars().all()}

    async def score_history(self, risk_id: UUID, limit: int = 100) -> List[RiskScore]:
        rows = await self.db.execute(
            select(RiskScore).where(RiskScore.risk_id == risk_id)
            .order_by(RiskScore.calculation_timestamp.desc()).limit(limit)
        )
        return list(rows.scalars().all())

    # ---------------------------------------------------------------- scoring
    async def _event_counts(self, asset_ids: List[UUID]) -> Dict[UUID, Tuple[int, int]]:
        """(events in last 24h, events in the 24h before) per asset, severity >= medium."""
        if not asset_ids:
            return {}
        now = datetime.utcnow()
        t24, t48 = now - timedelta(hours=24), now - timedelta(hours=48)
        sev = [LogSeverity.MEDIUM, LogSeverity.HIGH, LogSeverity.CRITICAL]
        out: Dict[UUID, List[int]] = {a: [0, 0] for a in asset_ids}
        for idx, (lo, hi) in enumerate(((t24, now), (t48, t24))):
            rows = await self.db.execute(
                select(SecurityLog.asset_id, func.count(SecurityLog.id))
                .where(SecurityLog.asset_id.in_(asset_ids), SecurityLog.severity.in_(sev),
                       SecurityLog.created_at >= lo, SecurityLog.created_at < hi)
                .group_by(SecurityLog.asset_id)
            )
            for aid, n in rows.all():
                out[aid][idx] = n
        return {k: (v[0], v[1]) for k, v in out.items()}

    async def score_risk(
        self,
        risk: Risk,
        events: Tuple[int, int] = (0, 0),
        force_history: bool = False,
    ) -> Risk:
        """Recompute BWVS, freshness, trend and priority for a risk (in place)."""
        cve, asset = risk.cve, risk.asset
        analysis = dict(risk.ai_analysis or {})
        source = analysis.get("source", "heuristic")

        if source in ("gemini", "agents") and risk.ai_relevance_score:
            ai_pct = risk.ai_relevance_score
        else:
            ai_pct, factors = heuristic_relevance(cve, asset, int(analysis.get("match_score", 0)))
            analysis.update({"source": "heuristic", "factors": factors})
            risk.ai_relevance_score = ai_pct
            risk.ai_analysis = analysis

        if cve is not None:
            cvss = cve.cvss_score or 0.0
            if not cvss and cve.cisa_kev:
                # KEV entries carry no CVSS until NVD enrichment: apply a documented floor.
                cvss = 7.0
                analysis["cvss_estimated"] = True
                risk.ai_analysis = analysis
            exploit = cve.exploit_activity_score
        else:
            sev = analysis.get("log_severity", "medium")
            cvss = LOG_SEVERITY_CVSS.get(sev, 5.5)
            exploit = 10 if risk.source == "log_correlation" else 6

        score = self.calculator.calculate(
            cvss_score=cvss,
            exploit_activity_score=exploit,
            exposure_score=asset.exposure_score if asset else 4,
            criticality_score=asset.criticality_score if asset else 3,
            business_impact_score=asset.business_impact_score if asset else 3,
            ai_relevance_percentage=ai_pct,
        )

        latest = (
            await self.db.execute(
                select(RiskScore).where(RiskScore.risk_id == risk.id)
                .order_by(RiskScore.calculation_timestamp.desc()).limit(1)
            )
        ).scalar_one_or_none()
        if force_history or latest is None or abs(latest.final_bwvs - score["final_bwvs"]) > 0.001:
            self.db.add(RiskScore(
                risk_id=risk.id, cvss_score=score["cvss_score"], exploit_activity=score["exploit_activity"],
                exposure_level=score["exposure_level"], asset_criticality=score["asset_criticality"],
                business_impact=score["business_impact"], ai_relevance=score["ai_relevance"],
                final_bwvs=score["final_bwvs"], calculation_timestamp=datetime.utcnow(),
            ))

        trend = calculate_trend_factor(
            cisa_kev=bool(cve and cve.cisa_kev),
            ransomware_use=bool(cve and cve.kev_ransomware_use),
            has_public_exploit=bool(cve and cve.has_exploit),
            epss=cve.epss_score if cve else None,
            events_recent=events[0], events_previous=events[1],
        )
        if risk.source == "log_correlation":
            trend = max(trend, 1.5)

        risk.bwvs_score = score["final_bwvs"]
        risk.freshness_factor = calculate_freshness(risk.last_seen or risk.first_seen or datetime.utcnow())
        risk.trend_factor = trend
        risk.priority_score = calculate_priority(risk.bwvs_score, risk.freshness_factor, risk.trend_factor)
        await self.db.flush()
        return risk

    async def refresh_all(self, commit_every: int = 0) -> Dict[str, Any]:
        """Re-score every open risk, refresh the Top-10 flags and store a snapshot."""
        rows = await self.db.execute(self._base_query().where(Risk.status.in_(OPEN_STATUSES)))
        risks = list(rows.scalars().all())
        events = await self._event_counts(list({r.asset_id for r in risks if r.asset_id}))
        for i, r in enumerate(risks, 1):
            await self.score_risk(r, events.get(r.asset_id, (0, 0)))
            if commit_every and i % commit_every == 0:
                await self.db.commit()
        ranked = sorted(risks, key=lambda r: r.priority_score, reverse=True)
        top_ids = {r.id for r in ranked[:10]}
        await self.db.execute(update(Risk).values(is_top_10=False))
        for r in risks:
            r.is_top_10 = r.id in top_ids
        await self.db.flush()
        await self.snapshot(risks)
        return {"rescored": len(risks), "top_10": len(top_ids)}

    async def snapshot(self, open_risks: Optional[List[Risk]] = None):
        from app.models.extras import RiskSnapshot

        if open_risks is None:
            rows = await self.db.execute(self._base_query().where(Risk.status.in_(OPEN_STATUSES)))
            open_risks = list(rows.scalars().all())
        buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in open_risks:
            buckets[risk_level(r.bwvs_score or 0)] += 1
        avg = sum(r.bwvs_score or 0 for r in open_risks) / len(open_risks) if open_risks else 0.0
        snap = RiskSnapshot(
            captured_at=datetime.utcnow(), open_total=len(open_risks), avg_bwvs=round(avg, 2),
            exposure_lakhs=expected_loss(open_risks)["total_lakhs"], **buckets,
        )
        self.db.add(snap)
        await self.db.flush()
        return snap

    # ------------------------------------------------------------ correlation
    async def _upsert_cve_risk(self, cve: CVE, asset: Asset, match_score: int, reasons: List[str]) -> Tuple[Risk, bool]:
        existing = (
            await self.db.execute(
                self._base_query().where(Risk.cve_id == cve.id, Risk.asset_id == asset.id)
            )
        ).scalar_one_or_none()
        if existing:
            # Keep the risk alive only if new evidence arrived (e.g. newly KEV-listed).
            if cve.cisa_kev and "listed in CISA KEV" not in (existing.match_reasons or []):
                existing.match_reasons = list(existing.match_reasons or []) + ["listed in CISA KEV"]
                existing.last_seen = datetime.utcnow()
            return existing, False
        risk = Risk(
            title=f"{cve.cve_id} on {asset.name}",
            description=(
                f"{cve.cve_id} ({(cve.severity or 'unrated').title()}, CVSS {cve.cvss_score or 0:.1f}) affects "
                f"{', '.join(reasons)} on {asset.name}. {(cve.description or '')[:600]}"
            ),
            cve_id=cve.id, asset_id=asset.id, source="cve_correlation", category="vulnerability",
            match_reasons=reasons, status=RiskStatus.ACTIVE,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
            remediation_notes=self._remediation(cve),
            ai_analysis={"source": "heuristic", "match_score": match_score},
        )
        risk.cve, risk.asset = cve, asset
        self.db.add(risk)
        await self.db.flush()
        await self.score_risk(risk)
        return risk, True

    @staticmethod
    def _remediation(cve: CVE) -> str:
        steps = ["Apply the vendor security update or mitigation referenced in the advisory."]
        if cve.cisa_kev:
            steps.insert(0, "Known exploited vulnerability: remediate immediately per CISA KEV guidance.")
        if (cve.attack_vector or "").upper() == "NETWORK":
            steps.append("Restrict network access to the affected service until patched.")
        return " ".join(steps)

    async def correlate_cve(self, cve: CVE, assets: Optional[List[Asset]] = None) -> Tuple[int, int]:
        if assets is None:
            assets = list((await self.db.execute(select(Asset).where(Asset.is_active == True))).scalars().all())  # noqa: E712
        created = touched = 0
        for asset in assets:
            matches = match_asset_versioned(cve.affected_software or [], cve.version_ranges or [], asset.software or [], asset.os)
            if not matches or matches[0].score < MIN_MATCH_SCORE:
                continue
            _, is_new = await self._upsert_cve_risk(cve, asset, matches[0].score, [m.reason for m in matches[:3]])
            created += int(is_new)
            touched += 1
        await self._resolve_patched(cve, assets)
        return created, touched

    async def _resolve_patched(self, cve: CVE, assets: List[Asset]) -> None:
        """Close untouched auto-created risks whose asset no longer matches (software upgraded past the affected range)."""
        if not cve.version_ranges:
            return  # without NVD version bounds we can never prove a risk was patched
        by_id = {a.id: a for a in assets}
        rows = (await self.db.execute(
            self._base_query().where(Risk.cve_id == cve.id, Risk.source == "cve_correlation", Risk.status == RiskStatus.ACTIVE)
        )).scalars().all()
        for risk in rows:
            asset = by_id.get(risk.asset_id)
            if asset is None:
                continue
            matches = match_asset_versioned(cve.affected_software or [], cve.version_ranges or [], asset.software or [], asset.os)
            if not matches or matches[0].score < MIN_MATCH_SCORE:
                await self.set_status(risk, RiskStatus.RESOLVED, "Auto-resolved: installed version is outside the affected range")

    async def correlate_asset(self, asset: Asset) -> int:
        cves = (await self.db.execute(select(CVE))).scalars().all()
        created = 0
        for cve in cves:
            c, _ = await self.correlate_cve(cve, [asset])
            created += c
        return created

    async def correlate_all(self, commit_every: int = 0) -> Dict[str, int]:
        """``commit_every`` releases the write lock periodically (background jobs on SQLite)."""
        assets = list((await self.db.execute(select(Asset).where(Asset.is_active == True))).scalars().all())  # noqa: E712
        cves = list((await self.db.execute(select(CVE))).scalars().all())
        created = 0
        for i, cve in enumerate(cves, 1):
            c, _ = await self.correlate_cve(cve, assets)
            created += c
            if commit_every and i % commit_every == 0:
                await self.db.commit()
        return {"cves": len(cves), "assets": len(assets), "risks_created": created}

    # --------------------------------------------------------- threat risks
    async def upsert_threat_risk(
        self, asset: Asset, category: str, severity: str, events: int, sample_message: str
    ) -> Tuple[Risk, bool]:
        """Risk derived from live security events against an asset."""
        title = f"{category.replace('_', ' ').title()} activity on {asset.name}"
        existing = (
            await self.db.execute(
                self._base_query().where(
                    Risk.asset_id == asset.id, Risk.source == "log_correlation", Risk.title == title,
                    Risk.status.in_(OPEN_STATUSES),
                )
            )
        ).scalar_one_or_none()
        now = datetime.utcnow()
        if existing:
            existing.last_seen = now
            existing.description = f"{events} correlated events in the last 24h. Latest: {sample_message}"
            existing.ai_analysis = {**(existing.ai_analysis or {}), "log_severity": severity, "events": events}
            await self.score_risk(existing, (events, 0))
            return existing, False
        risk = Risk(
            title=title, category=category, source="log_correlation", status=RiskStatus.ACTIVE,
            description=f"{events} correlated events in the last 24h. Latest: {sample_message}",
            asset_id=asset.id, first_seen=now, last_seen=now,
            match_reasons=[f"{events} {category} events"],
            ai_analysis={"source": "heuristic", "log_severity": severity, "events": events},
            remediation_notes="Investigate the source of the activity, block malicious indicators and review affected accounts.",
        )
        risk.asset, risk.cve = asset, None
        self.db.add(risk)
        await self.db.flush()
        await self.score_risk(risk, (events, 0))
        return risk, True

    # ----------------------------------------------------------------- status
    async def create_manual(self, title: str, description: Optional[str], asset: Optional[Asset], cve: Optional[CVE]) -> Risk:
        now = datetime.utcnow()
        risk = Risk(
            title=title, description=description, asset_id=asset.id if asset else None,
            cve_id=cve.id if cve else None, source="manual", category="manual",
            first_seen=now, last_seen=now, match_reasons=["manually registered"],
            ai_analysis={"source": "heuristic", "match_score": 100 if cve and asset else 0},
        )
        risk.asset, risk.cve = asset, cve
        self.db.add(risk)
        await self.db.flush()
        await self.score_risk(risk)
        return risk

    async def set_status(self, risk: Risk, status: RiskStatus, notes: Optional[str] = None) -> Risk:
        risk.status = status
        if notes:
            risk.remediation_notes = notes
        risk.resolved_at = datetime.utcnow() if status == RiskStatus.RESOLVED else None
        if status in (RiskStatus.RESOLVED, RiskStatus.ACCEPTED):
            risk.is_top_10 = False
        await self.db.flush()
        return risk

    async def statistics(self) -> Dict[str, Any]:
        rows = await self.db.execute(self._base_query())
        risks = list(rows.scalars().all())
        open_r = [r for r in risks if r.status in OPEN_STATUSES]
        by_status: Dict[str, int] = {}
        for r in risks:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in open_r:
            by_level[risk_level(r.bwvs_score or 0)] += 1
        avg = sum(r.bwvs_score or 0 for r in open_r) / len(open_r) if open_r else 0.0
        return {
            "total": len(risks), "open": len(open_r), "by_status": by_status, "by_level": by_level,
            "average_bwvs": round(avg, 2),
            "kev_open": sum(1 for r in open_r if r.cve and r.cve.cisa_kev),
        }
