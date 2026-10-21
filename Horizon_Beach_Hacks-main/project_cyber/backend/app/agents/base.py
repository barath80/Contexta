"""
Contexta Backend - Base SOC agent

Every agent:
  * receives the shared evidence pack and the discussion so far;
  * replies with a short message addressed to its colleagues plus structured
    findings (severity, confidence, key points, recommendations, agent-specific
    data) that the orchestrator and the risk engine consume;
  * has a deterministic rules-based fallback grounded in the same evidence, used
    when no AI provider is configured.
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List

import structlog

from app.ai.gemini import AIUnavailable

logger = structlog.get_logger()

SEVERITIES = ("low", "medium", "high", "critical")
MAX_EVIDENCE_CHARS = 14000


def clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(round(float(value)))))
    except (TypeError, ValueError):
        return default


def as_str_list(value: Any, limit: int = 6, max_len: int = 240) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        text = item if isinstance(item, str) else json.dumps(item, default=str)
        text = text.strip()
        if text:
            out.append(text[:max_len])
    return out[:limit]


def compact_evidence(evidence: Dict[str, Any]) -> str:
    """Serialise the evidence pack, trimming the bulkiest sections if needed."""
    data = dict(evidence)
    text = json.dumps(data, default=str, separators=(",", ":"))
    for key in ("recent_events", "same_cve_other_assets", "related_risks_same_asset", "previous_assessments"):
        if len(text) <= MAX_EVIDENCE_CHARS:
            break
        if isinstance(data.get(key), list):
            data[key] = data[key][: max(3, len(data[key]) // 2)]
            text = json.dumps(data, default=str, separators=(",", ":"))
    return text[:MAX_EVIDENCE_CHARS * 2]


class BaseAgent(ABC):
    agent_type: str = ""
    name: str = ""
    role: str = ""
    questions: List[str] = []
    data_contract: str = "{}"

    # ---------------------------------------------------------------- prompts
    def system_prompt(self) -> str:
        return (
            f"You are the {self.name} in an enterprise Security Operations Center AI team. {self.role}\n"
            "Hard rules:\n"
            "- Use ONLY facts present in the EVIDENCE. Never invent hosts, IP addresses, CVEs, actors, dates or numbers.\n"
            "- If the evidence cannot support a conclusion, say so explicitly and state what is missing.\n"
            "- Speak in the first person to your colleagues, briefly (max 110 words). When you build on or disagree "
            "with a colleague, name them (e.g. \"Building on Intel's point about KEV listing...\").\n"
            "- Severity values must be one of: low, medium, high, critical.\n"
            "- Respond with a single JSON object and nothing else."
        )

    def build_prompt(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> str:
        discussion = "\n".join(
            f"[{m['name']}] (severity={m.get('severity')}, confidence={m.get('confidence')}) {m['message']}"
            for m in transcript
        ) or "(you speak first)"
        questions = "\n".join(f"- {q}" for q in self.questions)
        return (
            f"EVIDENCE (JSON, authoritative):\n{compact_evidence(evidence)}\n\n"
            f"TEAM DISCUSSION SO FAR:\n{discussion}\n\n"
            f"YOUR TASK - answer these from the evidence:\n{questions}\n\n"
            "Return JSON with exactly these keys:\n"
            '{"message": "<=110 words to your colleagues", "severity": "low|medium|high|critical", '
            '"confidence": <0-100 integer>, "key_points": ["<=5 short facts"], '
            '"recommendations": ["<=5 concrete actions"], "addresses": ["agent types you responded to"], '
            f'"data": {self.data_contract}}}'
        )

    # --------------------------------------------------------------- execution
    async def respond(self, ai: Any, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        raw = await ai.generate_json(self.build_prompt(evidence, transcript), system=self.system_prompt(),
                                     temperature=0.3, max_tokens=1800)
        return self.normalise(raw, evidence)

    def respond_rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.normalise(self.rules(evidence, transcript), evidence)

    @abstractmethod
    def rules(self, evidence: Dict[str, Any], transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Deterministic reply built only from the evidence."""

    def normalise(self, raw: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
        message = str(raw.get("message") or "").strip()
        if not message:
            raise AIUnavailable(f"{self.name} returned an empty message", "ai_bad_response")
        severity = str(raw.get("severity", "")).lower().strip()
        if severity not in SEVERITIES:
            severity = (evidence.get("risk") or {}).get("level", "medium")
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        return {
            "agent": self.agent_type,
            "name": self.name,
            "message": message[:1400],
            "severity": severity,
            "confidence": clamp_int(raw.get("confidence"), 0, 100, 60),
            "key_points": as_str_list(raw.get("key_points"), 5),
            "recommendations": as_str_list(raw.get("recommendations"), 5),
            "addresses": [a for a in as_str_list(raw.get("addresses"), 5, 20)
                          if a in ("analyst", "intel", "forensics", "business", "response")],
            "data": data,
        }


# Shared helpers for the rules engines --------------------------------------
def level_of(evidence: Dict[str, Any]) -> str:
    return (evidence.get("risk") or {}).get("level", "medium")


def asset_label(evidence: Dict[str, Any]) -> str:
    a = evidence.get("asset") or {}
    return a.get("name") or "the affected asset"


def prior(transcript: List[Dict[str, Any]], agent: str) -> Dict[str, Any]:
    return next((m for m in transcript if m["agent"] == agent), {})
