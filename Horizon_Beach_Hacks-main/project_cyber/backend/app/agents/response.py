"""
Contexta Backend - Response Coordinator Agent (containment, recovery, playbook)
"""

from typing import Any, Dict, List

from app.agents.base import BaseAgent, asset_label, level_of, prior


class ResponseAgent(BaseAgent):
    agent_type = "response"
    name = "Response Coordinator"
    role = (
        "You turn the team's findings into an ordered response plan and choose the playbook to run. "
        "You speak last, so you must reference what Analyst, Intel, Forensics and Business established. "
        "Only recommend a playbook from the PLAYBOOKS list in the evidence."
    )
    questions = [
        "Which playbook should be run (slug from the evidence) and why?",
        "What must happen in the first hour (containment) versus the following days (eradication/recovery)?",
        "Does the Business impact justify escalation, and to whom?",
        "How will we know the risk is resolved (verification)?",
    ]
    data_contract = (
        '{"playbook_slug": "slug from evidence or null", "priority": "low|medium|high|critical", '
        '"immediate_actions": ["first hour"], "containment": ["..."], "recovery": ["..."], '
        '"escalate": true|false, "verification": "how closure is verified"}'
    )

    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        risk, cve = evidence.get("risk") or {}, evidence.get("cve") or {}
        pbs = evidence.get("playbooks") or []
        analyst, forensics, business = (prior(transcript, a) for a in ("analyst", "forensics", "business"))
        top = pbs[0] if pbs else None
        sevs = [m["severity"] for m in transcript] + [level_of(evidence)]
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        priority = max(sevs, key=lambda s: rank.get(s, 1))
        compromised = bool(forensics and forensics["data"].get("compromise_confirmed"))
        impact = (business.get("data") or {}).get("impact_level", "moderate")
        escalate = priority in ("high", "critical") or impact in ("major", "catastrophic")

        immediate: List[str] = []
        containment: List[str] = []
        if compromised:
            immediate.append(f"Isolate {asset_label(evidence)} from the network")
            containment.append("Block attacker indicators and rotate credentials that touched the asset")
        if cve:
            immediate.append(f"Apply the vendor fix for {cve.get('cve_id')} or restrict network access to the affected service")
        if top:
            immediate.append(f"Start playbook '{top['name']}'")
        if not immediate:
            immediate.append("Assign an owner and schedule remediation within the SLA")
        recovery = ["Verify the fix with a re-scan or functional test", "Restore normal access and close the risk with evidence"]

        parts = []
        if analyst or forensics or business:
            parts.append(f"Synthesising the team: priority {priority}"
                         + (f", business impact {impact}" if business else "")
                         + (", compromise indicated" if compromised else ", no confirmed compromise") + ".")
        if top:
            parts.append(f"Recommended playbook: {top['name']} ({'; '.join(top['reasons'][:2])}).")
        parts.append("First hour: " + "; ".join(immediate[:3]) + ".")
        if escalate:
            parts.append("Escalate to the security lead and asset owner.")
        return {
            "message": " ".join(parts),
            "severity": priority,
            "confidence": 80,
            "key_points": immediate[:3],
            "recommendations": immediate[:3] + containment[:2],
            "addresses": [a for a in ("analyst", "intel", "forensics", "business") if prior(transcript, a)],
            "data": {
                "playbook_slug": top["slug"] if top else None, "priority": priority,
                "immediate_actions": immediate, "containment": containment, "recovery": recovery,
                "escalate": escalate, "verification": "Re-scan the asset and confirm no open events for 24h",
            },
        }
