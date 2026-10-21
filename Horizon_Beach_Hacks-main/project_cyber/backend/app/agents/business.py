"""
Contexta Backend - Business Impact Agent
"""

from typing import Any, Dict, List

from app.agents.base import BaseAgent, asset_label, level_of, prior
from app.config import settings
from app.services.risk_service import exploit_probability


class BusinessAgent(BaseAgent):
    agent_type = "business"
    name = "Business Impact Analyst"
    role = (
        "You translate technical findings into business impact for executives: revenue at risk, downtime, "
        "stakeholders and regulatory exposure. Money is expressed in INR lakhs (1 lakh = 100,000 INR). "
        "You build on the Forensics findings."
    )
    questions = [
        "What revenue per day is at risk on this asset and what downtime is plausible?",
        "Who are the affected business units/stakeholders and who must be informed?",
        "Which regulatory or contractual obligations could be triggered (use the organisation's configured frameworks only)?",
        "How does the business impact change the priority of this risk?",
    ]
    data_contract = (
        '{"impact_level": "low|moderate|major|catastrophic", "daily_revenue_at_risk_lakhs": <number>, '
        '"expected_downtime_days": <number>, "expected_loss_lakhs": <number>, "stakeholders": ["..."], '
        '"regulatory": ["..."], "communication": "who to inform and when"}'
    )

    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        asset = evidence.get("asset") or {}
        cve = evidence.get("cve") or {}
        org = evidence.get("organization") or {}
        forensics = prior(transcript, "forensics")
        daily = float(asset.get("daily_revenue_impact_lakhs") or 0)
        crit = asset.get("criticality", "dev_test")
        days = settings.expected_downtime_days_critical if crit in ("payment_payroll", "core_backend") else settings.expected_downtime_days_default
        p = exploit_probability(
            epss=cve.get("epss_score"), kev=bool(cve.get("cisa_kev")), cvss=float(cve.get("cvss_score") or 0),
            from_logs=(not cve and (evidence.get("risk") or {}).get("source") == "log_correlation"),
            exposure=asset.get("exposure", "internal") if asset.get("exposure") in ("internet_facing", "vpn", "internal", "isolated") else "internal",
        ) if asset else 0.0
        loss = round(daily * days * p, 2)
        worst = round(daily * days, 2)

        if crit == "payment_payroll" or worst >= 50:
            impact = "major" if p < 0.5 else "catastrophic"
        elif worst >= 10:
            impact = "major" if p >= 0.3 else "moderate"
        else:
            impact = "moderate" if worst >= 3 else "low"
        severity = {"low": "low", "moderate": "medium", "major": "high", "catastrophic": "critical"}[impact]

        frameworks = org.get("compliance_frameworks") or []
        regulatory = [f"Review {f} obligations for incident notification and evidence retention" for f in frameworks] or \
                     ["No compliance frameworks are configured in Settings, so no regulatory mapping can be made"]
        stakeholders = [s for s in (asset.get("owner"), f"{asset.get('business_unit')} leadership" if asset.get("business_unit") else None) if s]

        parts = []
        if forensics:
            parts.append(f"Taking Forensics' view ({'compromise indicated' if forensics['data'].get('compromise_confirmed') else 'no confirmed compromise'}) into account:")
        if asset:
            parts.append(f"{asset_label(evidence)} carries Rs {daily:.1f} lakh/day of revenue impact; "
                         f"assuming {days:g} day(s) of downtime the worst case is Rs {worst:.1f} lakh, "
                         f"probability-weighted exposure Rs {loss:.1f} lakh (p={p:.2f}).")
        else:
            parts.append("No asset is linked, so revenue impact cannot be quantified.")
        if stakeholders:
            parts.append("Inform " + " and ".join(stakeholders) + ".")
        return {
            "message": " ".join(parts),
            "severity": severity if asset else level_of(evidence),
            "confidence": 75 if asset else 40,
            "key_points": [parts[-2] if len(parts) > 1 else parts[0], f"Impact level: {impact}"],
            "recommendations": ["Escalate to the asset owner and security leadership" if impact in ("major", "catastrophic")
                                else "Track remediation within the standard SLA"],
            "addresses": ["forensics"] if forensics else [],
            "data": {
                "impact_level": impact, "daily_revenue_at_risk_lakhs": daily, "expected_downtime_days": days,
                "expected_loss_lakhs": loss, "stakeholders": stakeholders, "regulatory": regulatory,
                "communication": "Notify the asset owner immediately" if impact in ("major", "catastrophic") else "Include in the weekly risk report",
            },
        }
