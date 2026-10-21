"""
Contexta Backend - AI agent routes

Multi-agent discussions about a risk or incident. The streaming endpoint emits
Server-Sent Events so the UI shows the agents conversing in real time.
"""

import json
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import clamp_int
from app.agents.evidence import build_evidence
from app.agents.orchestrator import AGENTS, DiscussionError, run_discussion, serialize_discussion, stream_discussion
from app.ai.gemini import AIUnavailable, get_ai
from app.auth.jwt import get_current_user, require_analyst
from app.config import settings
from app.database import get_db
from app.models.extras import AgentDiscussion
from app.models.user import User
from app.services.incident_service import IncidentService
from app.services.risk_service import RiskService

logger = structlog.get_logger()
router = APIRouter()


class DiscussionRequest(BaseModel):
    risk_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    agents: Optional[List[str]] = Field(default=None, description="Subset of analyst, intel, forensics, business, response")


class AgentQuery(BaseModel):
    agent: str
    question: str = Field(min_length=3, max_length=2000)
    risk_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None


async def _resolve(req: DiscussionRequest, db: AsyncSession):
    if not req.risk_id and not req.incident_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide risk_id or incident_id")
    bad = [a for a in (req.agents or []) if a not in AGENTS]
    if bad:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown agents: {bad}. Valid: {list(AGENTS)}")
    risk = incident = None
    if req.risk_id:
        risk = await RiskService(db).get(req.risk_id)
        if risk is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk not found")
    if req.incident_id:
        incident = await IncidentService(db).get(req.incident_id)
        if incident is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return risk, incident


@router.get("/status")
async def agent_status(_: User = Depends(get_current_user)):
    ai = get_ai()
    configured = bool(getattr(ai, "configured", False))
    return {
        "mode": "ai" if configured else "rules",
        "provider": ai.label if configured else None,
        "ai_configured": configured,
        "note": None if configured else
        "GEMINI_API_KEY is not set: agents run in rules-engine mode (deterministic analysis of the evidence).",
        "agents": [
            {"type": a.agent_type, "name": a.name, "role": a.role, "questions": a.questions}
            for a in AGENTS.values()
        ],
        "pipeline": [["analyst", "intel"], ["forensics"], ["business"], ["response"], ["consensus"]],
    }


@router.post("/discussions/stream")
async def discussion_stream(req: DiscussionRequest, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    risk, incident = await _resolve(req, db)
    # Built here: the request session is closed before the streamed body runs.
    evidence = await build_evidence(db, risk=risk, incident=incident)

    async def events():
        try:
            async for event in stream_discussion(None, risk, incident, user.id, req.agents, evidence=evidence):
                yield f"data: {json.dumps(event, default=str)}\n\n"
        except Exception as exc:  # defensive: always terminate the stream cleanly
            logger.error("Discussion stream crashed", error=str(exc))
            yield f"data: {json.dumps({'type': 'error', 'code': 'internal', 'message': 'Discussion failed'})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/discussions", response_model=Dict[str, Any])
async def discussion(req: DiscussionRequest, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    risk, incident = await _resolve(req, db)
    try:
        return await run_discussion(db, risk, incident, user.id, req.agents)
    except DiscussionError as exc:
        code = 503 if exc.code.startswith("ai_") else 500
        raise HTTPException(code, {"code": exc.code, "message": str(exc)})


@router.get("/discussions", response_model=List[Dict[str, Any]])
async def list_discussions(
    risk_id: Optional[UUID] = None, incident_id: Optional[UUID] = None, limit: int = Query(10, ge=1, le=50),
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    q = select(AgentDiscussion).order_by(AgentDiscussion.created_at.desc()).limit(limit)
    if risk_id:
        q = q.where(AgentDiscussion.risk_id == risk_id)
    if incident_id:
        q = q.where(AgentDiscussion.incident_id == incident_id)
    return [serialize_discussion(d) for d in (await db.execute(q)).scalars().all()]


@router.get("/discussions/{discussion_id}", response_model=Dict[str, Any])
async def get_discussion(discussion_id: UUID, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(AgentDiscussion).where(AgentDiscussion.id == discussion_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discussion not found")
    return serialize_discussion(d)


@router.post("/query", response_model=Dict[str, Any])
async def query_agent(req: AgentQuery, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Ask one agent a free-form question about a risk/incident (requires the AI provider)."""
    if req.agent not in AGENTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown agent. Valid: {list(AGENTS)}")
    ai = get_ai()
    if not getattr(ai, "configured", False):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            {"code": "ai_not_configured", "message": "Free-form questions need GEMINI_API_KEY"})
    risk, incident = await _resolve(DiscussionRequest(risk_id=req.risk_id, incident_id=req.incident_id), db)
    evidence = await build_evidence(db, risk=risk, incident=incident)
    agent = AGENTS[req.agent]
    prompt = (
        f"EVIDENCE (JSON):\n{json.dumps(evidence, default=str)[:20000]}\n\nQUESTION FROM THE ANALYST:\n{req.question}\n\n"
        'Answer using only the evidence. Return JSON: {"answer": "...", "confidence": <0-100>, "evidence_used": ["..."]}'
    )
    try:
        out = await ai.generate_json(prompt, system=agent.system_prompt(), temperature=0.3, max_tokens=1200)
    except AIUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"code": exc.code, "message": str(exc)})
    return {"agent": req.agent, "answer": str(out.get("answer", ""))[:3000],
            "confidence": clamp_int(out.get("confidence"), 0, 100, 60), "evidence_used": out.get("evidence_used", [])}
