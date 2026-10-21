"""
Contexta Backend - Agent Orchestrator

Pipeline (each stage sees everything said in earlier stages):

    Stage 1  Analyst + Intel            (parallel)
    Stage 2  Forensics                  (reads Analyst + Intel)
    Stage 3  Business                   (reads Forensics and earlier)
    Stage 4  Response                   (reads everyone)
    Consensus  weighted severity vote, dissent, prioritised plan
    Risk feedback  Intel's relevance assessment re-scores the risk (BWVS)

``stream_discussion`` yields events so the UI can render the conversation live;
``run_discussion`` awaits the same pipeline and returns the final result.
"""

import asyncio
import time
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.analyst import AnalystAgent
from app.agents.base import SEVERITIES, BaseAgent
from app.agents.business import BusinessAgent
from app.agents.evidence import build_evidence, evidence_hash
from app.agents.forensics import ForensicsAgent
from app.agents.intel import IntelAgent
from app.agents.response import ResponseAgent
from app.ai.gemini import AIUnavailable, get_ai
from app.database import AsyncSessionLocal
from app.ledger.chain import LedgerEventTypes
from app.models.extras import AgentDiscussion
from app.models.incident import Incident, IncidentAnalysis
from app.models.risk import Risk
from app.risk_engine.ranking import risk_level
from app.services import ledger_service
from app.services.risk_service import RiskService

logger = structlog.get_logger()

AGENTS: Dict[str, BaseAgent] = {
    a.agent_type: a for a in (AnalystAgent(), IntelAgent(), ForensicsAgent(), BusinessAgent(), ResponseAgent())
}
STAGES: List[List[str]] = [["analyst", "intel"], ["forensics"], ["business"], ["response"]]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
THREAT_LEVEL = {"low": "guarded", "medium": "moderate", "high": "elevated", "critical": "severe"}


class DiscussionError(Exception):
    def __init__(self, message: str, code: str = "discussion_failed"):
        super().__init__(message)
        self.code = code


# ----------------------------------------------------------------- consensus
def compute_consensus(messages: List[Dict[str, Any]], evidence: Dict[str, Any]) -> Dict[str, Any]:
    votes = [(RANK[m["severity"]], max(1, m["confidence"]), m) for m in messages]
    if not votes:
        raise DiscussionError("No agent produced a result")
    total_conf = sum(c for _, c, _ in votes)
    weighted = sum(r * c for r, c, _ in votes) / total_conf
    bwvs_rank = RANK[(evidence.get("risk") or {}).get("level", "medium")]
    consensus_rank = max(round(weighted), bwvs_rank - 1)  # conservative: never far below the BWVS level
    consensus = SEVERITIES[min(3, consensus_rank)]

    ranks = [r for r, _, _ in votes]
    spread = max(ranks) - min(ranks)
    agreement = round(max(0.0, 1 - spread / 3), 2)
    dissent = [
        {"agent": m["agent"], "severity": m["severity"],
         "reason": (m["key_points"][0] if m["key_points"] else m["message"][:140])}
        for r, _, m in votes if abs(r - consensus_rank) >= 2
    ]

    by_agent = {m["agent"]: m for m in messages}
    findings = []
    for m in messages:
        for kp in m["key_points"][:2]:
            findings.append({"source": m["agent"], "finding": kp, "confidence": m["confidence"]})
    findings.sort(key=lambda f: f["confidence"], reverse=True)

    recs, seen = [], set()
    for agent in ("response", "forensics", "analyst", "intel", "business"):
        for r in (by_agent.get(agent) or {}).get("recommendations", []):
            if r.lower() not in seen:
                seen.add(r.lower())
                recs.append({"priority": len(recs) + 1, "recommendation": r, "source": agent})

    resp = (by_agent.get("response") or {}).get("data", {})
    available = {p["slug"] for p in evidence.get("playbooks", [])}
    playbook = resp.get("playbook_slug") if resp.get("playbook_slug") in available else \
        (evidence["playbooks"][0]["slug"] if evidence.get("playbooks") else None)
    immediate = [a for a in resp.get("immediate_actions", []) if isinstance(a, str)][:5]

    return {
        "consensus_severity": consensus,
        "threat_level": THREAT_LEVEL[consensus],
        "confidence_score": round(total_conf / len(votes)),
        "agent_agreement": {"score": agreement, "level": "high" if agreement >= 0.8 else "moderate" if agreement >= 0.5 else "low",
                            "agents_reporting": len(messages)},
        "dissent": dissent,
        "key_findings": findings[:8],
        "prioritized_recommendations": recs[:10],
        "immediate_actions": immediate,
        "recommended_playbook": playbook,
        "escalation_required": consensus in ("high", "critical") or bool(resp.get("escalate")),
        "executive_summary": "",
        "bwvs_level": (evidence.get("risk") or {}).get("level"),
    }


def template_summary(messages: List[Dict[str, Any]], consensus: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    risk = evidence.get("risk") or {}
    by = {m["agent"]: m for m in messages}
    parts = [f"{consensus['consensus_severity'].upper()} severity: {risk.get('title') or (evidence.get('incident') or {}).get('title')}."]
    a = (by.get("analyst") or {}).get("data", {})
    if a.get("classification"):
        parts.append(f"Classified as {a['classification']} (stage: {a.get('attack_stage', 'n/a').replace('_', ' ')}).")
    b = (by.get("business") or {}).get("data", {})
    if b.get("impact_level"):
        parts.append(f"Business impact {b['impact_level']}; expected loss Rs {b.get('expected_loss_lakhs', 0)} lakh.")
    if consensus.get("recommended_playbook"):
        parts.append(f"Recommended playbook: {consensus['recommended_playbook']}.")
    if consensus["dissent"]:
        parts.append("Dissent: " + ", ".join(d["agent"] for d in consensus["dissent"]) + ".")
    return " ".join(parts)


async def _llm_summary(ai: Any, messages: List[Dict[str, Any]], consensus: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    transcript = "\n".join(f"[{m['name']} | {m['severity']}] {m['message']}" for m in messages)
    prompt = (
        "You are the SOC lead. Write the executive summary (max 90 words, plain language, no invented facts) of this "
        f"team discussion. Consensus severity: {consensus['consensus_severity']}. Dissent: {consensus['dissent'] or 'none'}.\n\n"
        f"{transcript}\n\nReturn JSON: {{\"executive_summary\": \"...\"}}"
    )
    data = await ai.generate_json(prompt, system="You summarise SOC discussions faithfully.", temperature=0.2, max_tokens=500)
    text = str(data.get("executive_summary", "")).strip()
    if not text:
        raise AIUnavailable("empty summary", "ai_bad_response")
    return text[:900]


# ------------------------------------------------------------------- feedback
async def _apply_risk_feedback(risk_id: UUID, intel: Dict[str, Any], discussion_id: UUID) -> Optional[Dict[str, Any]]:
    """Feed the Intel agent's relevance assessment back into BWVS."""
    pct = (intel.get("data") or {}).get("relevance_percentage")
    try:
        pct = max(0.0, min(100.0, float(pct)))
    except (TypeError, ValueError):
        return None
    async with AsyncSessionLocal() as db:
        risks = RiskService(db)
        risk = await risks.get(risk_id)
        if risk is None:
            return None
        before = {"bwvs": risk.bwvs_score, "ai_relevance": risk.ai_relevance_score}
        risk.ai_relevance_score = pct
        risk.ai_analysis = {
            **(risk.ai_analysis or {}), "source": "agents", "discussion_id": str(discussion_id),
            "basis": (intel.get("data") or {}).get("relevance_basis", ""), "assessed_at": datetime.utcnow().isoformat(),
        }
        await risks.score_risk(risk, force_history=True)
        await db.commit()
        after = {"bwvs": risk.bwvs_score, "ai_relevance": risk.ai_relevance_score}
    await ledger_service.safe_record(
        LedgerEventTypes.RISK_CALCULATED, actor="agents", resource_type="risk", resource_id=str(risk_id),
        data={"before": before, "after": after, "source": "intel_agent", "discussion_id": str(discussion_id)},
    )
    return {"before": before, "after": after, "changed": abs(before["bwvs"] - after["bwvs"]) > 0.01}


# ------------------------------------------------------------------- pipeline
def serialize_discussion(d: AgentDiscussion) -> Dict[str, Any]:
    return {
        "id": d.id, "risk_id": d.risk_id, "incident_id": d.incident_id, "title": d.title, "status": d.status,
        "generated_by": d.generated_by, "messages": d.messages or [], "consensus": d.consensus or {},
        "risk_feedback": d.risk_feedback or {}, "evidence_hash": d.evidence_hash, "duration_ms": d.duration_ms,
        "error": d.error, "created_at": d.created_at,
    }


async def stream_discussion(
    db: AsyncSession,
    risk: Optional[Risk] = None,
    incident: Optional[Incident] = None,
    user_id: Optional[UUID] = None,
    agents: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> AsyncIterator[Dict[str, Any]]:
    """
    ``evidence`` may be pre-built by the caller. Streaming endpoints must do this
    because the request session is closed before the response body is produced.
    """
    selected = [a for a in (agents or list(AGENTS)) if a in AGENTS] or list(AGENTS)
    if evidence is None:
        evidence = await build_evidence(db, risk=risk, incident=incident)
    ai = get_ai()
    mode_ai = bool(getattr(ai, "configured", False))
    generated_by = ai.label if mode_ai else "rules-engine"
    title = (risk.title if risk else incident.title) if (risk or incident) else "Discussion"
    started = time.monotonic()

    async with AsyncSessionLocal() as s:
        row = AgentDiscussion(
            risk_id=risk.id if risk else (incident.risk_id if incident else None),
            incident_id=incident.id if incident else None, title=title, status="running",
            generated_by=generated_by, messages=[], consensus={}, evidence_hash=evidence_hash(evidence),
            created_by=user_id,
        )
        s.add(row)
        await s.commit()
        discussion_id = row.id

    yield {"type": "started", "discussion_id": str(discussion_id), "title": title, "generated_by": generated_by,
           "mode": "ai" if mode_ai else "rules", "agents": selected,
           "stages": [[a for a in st if a in selected] for st in STAGES if any(a in selected for a in st)]}

    messages: List[Dict[str, Any]] = []
    try:
        for stage_idx, stage in enumerate(STAGES):
            stage_agents = [a for a in stage if a in selected]
            if not stage_agents:
                continue
            yield {"type": "typing", "agents": stage_agents}
            snapshot = list(messages)

            async def run_one(agent_type: str):
                agent = AGENTS[agent_type]
                t0 = time.monotonic()
                degraded = None
                if mode_ai:
                    try:
                        out = await agent.respond(ai, evidence, snapshot)
                    except AIUnavailable as exc:
                        if stage_idx == 0 and not messages:
                            raise
                        logger.warning("Agent degraded to rules", agent=agent_type, error=str(exc))
                        out, degraded = agent.respond_rules(evidence, snapshot), f"{exc.code}: {exc}"
                else:
                    out = agent.respond_rules(evidence, snapshot)
                out["timestamp"] = datetime.utcnow().isoformat()
                out["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
                out["source"] = "rules-engine" if (not mode_ai or degraded) else ai.label
                if degraded:
                    out["degraded"] = degraded
                return out

            tasks = [asyncio.create_task(run_one(a)) for a in stage_agents]
            for fut in asyncio.as_completed(tasks):
                try:
                    msg = await fut
                except Exception:
                    for t in tasks:
                        t.cancel()
                    raise
                messages.append(msg)
                yield {"type": "message", "message": msg}

        consensus = compute_consensus(messages, evidence)
        template = template_summary(messages, consensus, evidence)
        if mode_ai:
            try:
                consensus["executive_summary"] = await _llm_summary(ai, messages, consensus, evidence)
            except AIUnavailable:
                consensus["executive_summary"] = template
        else:
            consensus["executive_summary"] = template
        yield {"type": "consensus", "consensus": consensus}

        feedback: Dict[str, Any] = {}
        intel = next((m for m in messages if m["agent"] == "intel"), None)
        if mode_ai and intel and row.risk_id and not intel.get("degraded"):
            fb = await _apply_risk_feedback(row.risk_id, intel, discussion_id)
            if fb:
                feedback = fb
                yield {"type": "risk_feedback", "feedback": fb}

        duration = int((time.monotonic() - started) * 1000)
        async with AsyncSessionLocal() as s:
            d = await s.get(AgentDiscussion, discussion_id)
            d.messages, d.consensus, d.risk_feedback = messages, consensus, feedback
            d.status, d.duration_ms = "completed", duration
            if incident is not None:
                for m in messages:
                    s.add(IncidentAnalysis(
                        incident_id=incident.id, agent_type=m["agent"], analysis_result=m["data"],
                        confidence_score=float(m["confidence"]), recommendations=m["recommendations"],
                        raw_response=m["message"],
                    ))
                s.add(IncidentAnalysis(
                    incident_id=incident.id, agent_type="consensus", analysis_result=consensus,
                    confidence_score=float(consensus["confidence_score"]),
                    recommendations=[r["recommendation"] for r in consensus["prioritized_recommendations"]],
                    consensus_report=consensus["executive_summary"],
                ))
            await s.commit()
            await s.refresh(d)
            final = serialize_discussion(d)

        await ledger_service.safe_record(
            LedgerEventTypes.ANALYSIS_COMPLETE, actor=str(user_id) if user_id else "agents",
            resource_type="agent_discussion", resource_id=str(discussion_id),
            data={"risk_id": str(row.risk_id) if row.risk_id else None, "consensus": consensus["consensus_severity"],
                  "generated_by": generated_by, "evidence_sha256": final["evidence_hash"]},
        )
        yield {"type": "done", "discussion": final}
    except Exception as exc:
        code = getattr(exc, "code", "discussion_failed")
        logger.error("Agent discussion failed", error=str(exc), code=code)
        async with AsyncSessionLocal() as s:
            d = await s.get(AgentDiscussion, discussion_id)
            if d is not None:
                d.status, d.error, d.messages = "failed", str(exc)[:500], messages
                d.duration_ms = int((time.monotonic() - started) * 1000)
                await s.commit()
        yield {"type": "error", "code": code, "message": str(exc)}


async def run_discussion(
    db: AsyncSession,
    risk: Optional[Risk] = None,
    incident: Optional[Incident] = None,
    user_id: Optional[UUID] = None,
    agents: Optional[List[str]] = None,
) -> Dict[str, Any]:
    final = None
    async for event in stream_discussion(db, risk, incident, user_id, agents):
        if event["type"] == "done":
            final = event["discussion"]
        elif event["type"] == "error":
            raise DiscussionError(event["message"], event.get("code", "discussion_failed"))
    if final is None:
        raise DiscussionError("Discussion produced no result")
    return final
