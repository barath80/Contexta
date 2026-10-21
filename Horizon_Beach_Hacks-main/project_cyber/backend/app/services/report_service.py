"""
Contexta Backend - Report service

Board / executive reports. The narrative is written by Gemini from the live
executive metrics when configured; otherwise a deterministic report is
assembled from the same metrics. Reports are persisted and hash-logged.
"""

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gemini import AIUnavailable, get_ai
from app.models.extras import Report
from app.services import dashboard_service

logger = structlog.get_logger()


def _fmt_lakhs(value: float) -> str:
    if value >= 100:
        return f"Rs {value / 100:.2f} crore"
    return f"Rs {value:.1f} lakh"


def deterministic_report(ex: Dict[str, Any], overview: Dict[str, Any]) -> str:
    ch = ex["control_health"]
    lines = [
        f"# Board Risk Report - {datetime.utcnow():%d %b %Y}",
        "",
        "## Summary",
        f"- Business risk score: **{ex['business_risk_score']}/10** (trend: {ex['risk_trend']['label']})",
        f"- Expected financial exposure: **{_fmt_lakhs(ex['financial_exposure_lakhs'])}**",
        f"- Open risks: **{overview['open_risks']}** "
        f"({overview['risks_by_level']['critical']} critical, {overview['risks_by_level']['high']} high)",
        f"- Active incidents: **{overview['active_incidents']}**; threat level **{overview['threat_level']['level']}** "
        f"({overview['threat_level']['reason']})",
        "",
        "## Where the exposure sits",
    ]
    for u in ex["exposure_by_business_unit"][:5]:
        lines.append(f"- {u['name']}: {_fmt_lakhs(u['lakhs'])}")
    lines += ["", "## Control health",
              f"- Actively exploited (CISA KEV) vulnerabilities open: {ch['kev_open']}",
              f"- Internet-facing assets with high/critical risk: {ch['internet_facing_assets_with_serious_risk']}",
              f"- Critical risks open longer than {ch['critical_sla_days']} days: {ch['critical_sla_breaches']}",
              f"- Last 30 days: {ch['risks_opened_30d']} risks opened, {ch['risks_resolved_30d']} resolved"]
    if ch["mean_days_to_resolve"] is not None:
        lines.append(f"- Mean time to resolve a risk: {ch['mean_days_to_resolve']} days")
    lines += ["", "## Top exposed assets"]
    for a in ex["top_exposed_assets"][:5]:
        lines.append(f"- {a['asset_name']}: {_fmt_lakhs(a['expected_loss_lakhs'])} "
                     f"(p={a['probability']}, {a['open_risks']} open risks)")
    lines += ["", "## Methodology", *[f"- {x}" for x in ex["assumptions"]]]
    return "\n".join(lines)


async def generate_board_report(db: AsyncSession, user_id: Optional[UUID], actor: str) -> Report:
    ex = await dashboard_service.executive(db)
    ov = await dashboard_service.overview(db)
    ai = get_ai()
    generated_by = "rules-engine"
    content = deterministic_report(ex, ov)
    if getattr(ai, "configured", False):
        prompt = (
            "Write a board-level cyber risk report in Markdown (max 450 words) for non-technical directors. "
            "Use ONLY the metrics below; do not invent numbers. Sections: Headline, What changed, Where the money is at risk, "
            "Decisions needed. Amounts are INR lakhs (100 lakh = 1 crore).\n\n"
            f"EXECUTIVE METRICS: {ex}\nOVERVIEW: {ov}"
        )
        try:
            text = await ai.generate_text(prompt, system="You are a CISO writing for the board.", temperature=0.3, max_tokens=1500)
            content = text.strip() + "\n\n---\n\n## Methodology\n" + "\n".join(f"- {x}" for x in ex["assumptions"])
            generated_by = ai.label
        except AIUnavailable as exc:
            logger.warning("Board report AI failed; using deterministic report", error=str(exc))
    report = Report(
        kind="board", title=f"Board Risk Report {datetime.utcnow():%Y-%m-%d}", content=content,
        params={}, metrics={"executive": ex, "overview": ov}, generated_by=generated_by, created_by=user_id,
    )
    db.add(report)
    await db.flush()
    return report


async def list_reports(db: AsyncSession, limit: int = 20):
    rows = await db.execute(select(Report).order_by(Report.created_at.desc()).limit(limit))
    return list(rows.scalars().all())


async def get_report(db: AsyncSession, report_id: UUID) -> Optional[Report]:
    return (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
