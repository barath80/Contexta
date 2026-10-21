"""
Contexta Backend - Digital Forensics Agent (timeline, artifacts, preservation)
"""

from typing import Any, Dict, List

from app.agents.base import BaseAgent, asset_label, level_of, prior

_ARTIFACTS = {
    "server": ["authentication logs", "process execution logs", "web/application server logs", "memory image"],
    "database": ["database audit/query logs", "authentication logs", "backup integrity", "memory image"],
    "application": ["application logs", "reverse-proxy/WAF logs", "deployment history", "container image digests"],
    "network_device": ["configuration backup", "syslog", "admin session history", "firmware hash"],
    "workstation": ["EDR telemetry", "browser history", "prefetch/registry artefacts", "memory image"],
    "cloud_service": ["cloud audit trail", "IAM change history", "object access logs", "VPC flow logs"],
    "iot_device": ["firmware image", "network flow records", "management-interface logs"],
}


class ForensicsAgent(BaseAgent):
    agent_type = "forensics"
    name = "Digital Forensics Analyst"
    role = (
        "You reconstruct what happened and when from the recorded events, decide what evidence must be preserved "
        "and state what the evidence can and cannot prove. You build on the Analyst's and Intel's findings."
    )
    questions = [
        "What does the event timeline show, and does it support the Analyst's and Intel's assessments?",
        "Which indicators of compromise are present in the evidence?",
        "What artefacts must be preserved from this asset, and in what order?",
        "What are the evidence gaps that limit our confidence?",
    ]
    data_contract = (
        '{"timeline": ["time - event"], "indicators_present": ["from evidence"], '
        '"artifacts_to_preserve": ["..."], "evidence_gaps": ["..."], "compromise_confirmed": true|false}'
    )

    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        events = sorted(evidence.get("recent_events", []), key=lambda e: e["time"])
        asset = evidence.get("asset") or {}
        analyst, intel = prior(transcript, "analyst"), prior(transcript, "intel")
        timeline = [f"{e['time'][:19]} - {e['category']} ({e['severity']}) from {e.get('src_ip') or 'n/a'}: {e['message'][:90]}"
                    for e in events[-8:]]
        serious = [e for e in events if e["severity"] in ("high", "critical")]
        indicators = evidence.get("indicators") or {}
        ioc_list = [f"{k}: {', '.join(v[:3])}" for k, v in indicators.items()]
        gaps = []
        if not events:
            gaps.append("No security events recorded for this asset - exploitation cannot be confirmed or excluded")
        if not asset.get("hostname"):
            gaps.append("Asset hostname missing - correlation by IP only")
        if evidence.get("cve") and not serious:
            gaps.append("No exploitation telemetry (EDR/WAF) is linked to this CVE on this asset")
        artifacts = _ARTIFACTS.get(asset.get("type", "server"), _ARTIFACTS["server"])

        parts = []
        if analyst:
            parts.append(f"Analyst rated this {analyst['severity']}; checking the telemetry against that.")
        if events:
            parts.append(f"I see {len(events)} events ({len(serious)} high/critical); earliest {events[0]['time'][:19]}, latest {events[-1]['time'][:19]}.")
        else:
            parts.append(f"There are no recorded events for {asset_label(evidence)}.")
        if ioc_list:
            parts.append("Indicators present: " + "; ".join(ioc_list) + ".")
        if intel and intel["data"].get("ttps"):
            parts.append("Intel's techniques to hunt: " + ", ".join(t["id"] for t in intel["data"]["ttps"]) + ".")
        parts.append("Preserve in order of volatility: " + ", ".join(artifacts[:3]) + ".")

        severity = "critical" if len([e for e in serious if e["severity"] == "critical"]) else ("high" if serious else level_of(evidence))
        return {
            "message": " ".join(parts),
            "severity": severity,
            "confidence": 80 if events else 50,
            "key_points": (timeline[-2:] or ["No event timeline available"]) + gaps[:1],
            "recommendations": [f"Preserve: {a}" for a in artifacts[:3]] + ["Hash and log every evidence item to the audit ledger"],
            "addresses": [a for a in ("analyst", "intel") if prior(transcript, a)],
            "data": {
                "timeline": timeline, "indicators_present": ioc_list, "artifacts_to_preserve": artifacts,
                "evidence_gaps": gaps, "compromise_confirmed": bool(serious and any(e["category"] in ("malware_alert", "data_exfiltration", "privilege_escalation") for e in serious)),
            },
        }
