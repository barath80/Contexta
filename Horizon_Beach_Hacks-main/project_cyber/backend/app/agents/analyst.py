"""
Contexta Backend - Security Analyst Agent (triage and classification)
"""

from typing import Any, Dict, List

from app.agents.base import BaseAgent, asset_label, level_of


class AnalystAgent(BaseAgent):
    agent_type = "analyst"
    name = "Security Analyst"
    role = (
        "You perform first-line triage: classify the threat, judge how far an attacker has progressed, "
        "identify the affected systems and set the initial severity."
    )
    questions = [
        "What type of threat is this and what is its attack vector?",
        "Is there evidence of active exploitation in the recent events, or is this exposure only?",
        "Which systems are affected and how exposed are they?",
        "What is your initial severity and how confident are you?",
    ]
    data_contract = (
        '{"classification": "short threat class", "attack_stage": "exposure|exploitation_attempt|'
        'compromise_suspected|post_compromise", "affected_systems": ["names from evidence"], '
        '"exploitability": "active|likely|possible|unlikely"}'
    )

    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        risk, cve, asset = evidence.get("risk") or {}, evidence.get("cve"), evidence.get("asset") or {}
        events = evidence.get("recent_events") or []
        serious = [e for e in events if e["severity"] in ("high", "critical")]
        level = level_of(evidence)

        if cve:
            classification = f"Exploitable vulnerability {cve['cve_id']}"
            vector = (cve.get("attack_vector") or "unspecified").lower()
        else:
            classification = (risk.get("category") or "security event").replace("_", " ").title()
            vector = "observed in telemetry"

        if serious:
            stage, exploitability = "exploitation_attempt", "active"
        elif cve and (cve.get("cisa_kev") or (cve.get("epss_score") or 0) >= 0.5):
            stage, exploitability = "exposure", "likely"
        else:
            stage, exploitability = "exposure", "possible"

        parts = [
            f"{risk.get('title')}: BWVS {risk.get('bwvs_score')} ({level}), priority {risk.get('priority_score')}.",
            f"{asset_label(evidence)} is {asset.get('exposure', 'unknown').replace('_', ' ')} "
            f"({asset.get('criticality', 'unknown').replace('_', ' ')}).",
        ]
        if cve:
            signals = []
            if cve.get("cisa_kev"):
                signals.append("CISA KEV-listed")
            if cve.get("epss_score") is not None:
                signals.append(f"EPSS {cve['epss_score']:.0%}")
            if cve.get("exploit_sources"):
                signals.append("public exploit code")
            parts.append(f"CVSS {cve.get('cvss_score')}, {vector} vector" + (f"; {', '.join(signals)}." if signals else "."))
        if events:
            parts.append(f"{len(events)} recent events on this asset, {len(serious)} high/critical.")
        else:
            parts.append("No security events are recorded against this asset, so I can confirm exposure but not exploitation.")

        recs = []
        if cve and cve.get("cisa_kev"):
            recs.append("Treat as actively exploited: remediate within the CISA KEV due date")
        if serious:
            recs.append("Open an incident and review the high-severity events")
        recs.append("Apply the vendor fix or restrict access to the affected service")
        return {
            "message": " ".join(parts),
            "severity": level,
            "confidence": 85 if events or cve else 60,
            "key_points": [p for p in parts[:3]],
            "recommendations": recs,
            "addresses": [],
            "data": {"classification": classification, "attack_stage": stage,
                     "affected_systems": [asset_label(evidence)], "exploitability": exploitability},
        }
