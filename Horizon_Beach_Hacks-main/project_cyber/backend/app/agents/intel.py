"""
Contexta Backend - Threat Intelligence Agent (CTI, TTPs, attribution)

Its ``relevance_percentage`` is fed back to the risk engine as the AI-relevance
component of BWVS.
"""

from typing import Any, Dict, List

from app.agents.base import BaseAgent, level_of

# Vulnerability class -> likely ATT&CK technique (used only by the rules fallback).
_CWE_TECHNIQUES = {
    "CWE-78": ("T1059", "Command and Scripting Interpreter"),
    "CWE-77": ("T1059", "Command and Scripting Interpreter"),
    "CWE-94": ("T1059", "Command and Scripting Interpreter"),
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),
    "CWE-22": ("T1190", "Exploit Public-Facing Application"),
    "CWE-434": ("T1190", "Exploit Public-Facing Application"),
    "CWE-502": ("T1190", "Exploit Public-Facing Application"),
    "CWE-918": ("T1190", "Exploit Public-Facing Application"),
    "CWE-287": ("T1078", "Valid Accounts"),
    "CWE-306": ("T1078", "Valid Accounts"),
    "CWE-798": ("T1078", "Valid Accounts"),
    "CWE-269": ("T1068", "Exploitation for Privilege Escalation"),
    "CWE-250": ("T1068", "Exploitation for Privilege Escalation"),
    "CWE-119": ("T1203", "Exploitation for Client Execution"),
    "CWE-787": ("T1203", "Exploitation for Client Execution"),
    "CWE-416": ("T1203", "Exploitation for Client Execution"),
}


class IntelAgent(BaseAgent):
    agent_type = "intel"
    name = "Threat Intelligence Analyst"
    role = (
        "You provide cyber threat intelligence: exploitation in the wild, likely techniques (MITRE ATT&CK), "
        "campaign/actor context supported by the evidence, and how relevant this threat is to THIS organisation."
    )
    questions = [
        "Is this being exploited in the wild (KEV, EPSS, public exploits, ransomware use)?",
        "Which MITRE ATT&CK techniques fit, based on the vulnerability class and the observed events?",
        "Can the evidence support attribution? If not, say it cannot - do not guess actors.",
        "How relevant is this to this organisation and asset (0-100)? Explain the basis.",
    ]
    data_contract = (
        '{"in_the_wild": true|false, "threat_actors": ["only if supported by evidence"], '
        '"ttps": [{"id": "T1190", "name": "..."}], "iocs": ["from evidence only"], '
        '"relevance_percentage": <0-100>, "relevance_basis": "one sentence"}'
    )

    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        risk, cve, asset = evidence.get("risk") or {}, evidence.get("cve"), evidence.get("asset") or {}
        ttps: Dict[str, str] = {}
        if cve:
            for cwe in cve.get("cwes", []):
                if cwe in _CWE_TECHNIQUES:
                    tid, name = _CWE_TECHNIQUES[cwe]
                    ttps[tid] = name
            if not ttps and (cve.get("attack_vector") or "").upper() == "NETWORK" and asset.get("exposure") in ("internet_facing", "vpn"):
                ttps["T1190"] = "Exploit Public-Facing Application"
        cats = {e["category"] for e in evidence.get("recent_events", [])}
        if "brute_force" in cats or "login_failure" in cats:
            ttps["T1110"] = "Brute Force"
        if "port_scan" in cats:
            ttps["T1046"] = "Network Service Discovery"
        if "privilege_escalation" in cats:
            ttps["T1068"] = "Exploitation for Privilege Escalation"
        if "data_exfiltration" in cats:
            ttps["T1041"] = "Exfiltration Over C2 Channel"
        if "malware_alert" in cats:
            ttps["T1204"] = "User Execution"

        in_wild = bool(cve and (cve.get("cisa_kev") or cve.get("exploit_sources"))) or bool(cats)
        severity = level_of(evidence)
        parts = []
        if cve:
            if cve.get("cisa_kev"):
                parts.append(f"{cve['cve_id']} is in CISA's Known Exploited Vulnerabilities catalog - exploitation in the wild is confirmed.")
            if cve.get("kev_ransomware_use"):
                parts.append("CISA records use in ransomware campaigns.")
                severity = "critical"
            elif cve.get("cisa_kev") and severity in ("low", "medium"):
                severity = "high"
            if cve.get("epss_score") is not None:
                parts.append(f"EPSS puts exploitation probability at {cve['epss_score']:.0%} over 30 days (percentile {cve.get('epss_percentile') or 0:.0%}).")
            if cve.get("exploit_sources"):
                parts.append("Public exploit references: " + ", ".join(cve["exploit_sources"]) + ".")
            if not parts:
                parts.append(f"No exploitation signals are recorded for {cve['cve_id']} yet.")
        else:
            parts.append("This is a telemetry-derived threat, not a catalogued CVE.")
        if ttps:
            parts.append("Likely techniques: " + ", ".join(f"{k} {v}" for k, v in ttps.items()) + " (derived from the weakness class / observed events).")
        parts.append("Attribution is not possible from the available data; I will not name an actor." if not (cve and cve.get("kev_ransomware_use")) else
                     "Associated with ransomware operators per CISA; no specific group can be attributed from this data.")

        relevance = float(risk.get("ai_relevance_score") or 50)
        actors = ["Ransomware operators (CISA KEV: known ransomware campaign use)"] if cve and cve.get("kev_ransomware_use") else []
        return {
            "message": " ".join(parts),
            "severity": severity,
            "confidence": 85 if cve and (cve.get("cisa_kev") or cve.get("epss_score") is not None) else 65,
            "key_points": parts[:3],
            "recommendations": ["Prioritise remediation of actively exploited vulnerabilities",
                                "Hunt for the listed ATT&CK techniques in the affected asset's logs"] if ttps else
                               ["Monitor for exploitation indicators"],
            "addresses": ["analyst"] if transcript else [],
            "data": {
                "in_the_wild": in_wild, "threat_actors": actors,
                "ttps": [{"id": k, "name": v} for k, v in ttps.items()],
                "iocs": (evidence.get("indicators") or {}).get("ips", [])[:10],
                "relevance_percentage": round(relevance),
                "relevance_basis": "; ".join(risk.get("ai_relevance_basis") or []) or "heuristic scoring of match, exposure and exploitation signals",
            },
        }
