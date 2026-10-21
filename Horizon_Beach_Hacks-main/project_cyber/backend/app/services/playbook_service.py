"""
Contexta Backend - Playbook Service

Definitions are loaded from backend/playbooks/*.json (version controlled) and
may be extended via the API. Executions are durable state machines:

* automated steps run in-platform actions (isolate asset, block IOCs, evidence
  snapshot with integrity hash, related-asset scan, notifications);
* manual steps pause the execution until an analyst completes them;
* every state change is written to the audit ledger.
"""

import copy
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from uuid import UUID

import httpx
import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import BACKEND_DIR
from app.ledger.chain import LedgerEventTypes
from app.models.asset import Asset
from app.models.extras import AssetConnection, BlockedIndicator
from app.models.incident import Incident
from app.models.log import LogSeverity, SecurityLog
from app.models.playbook import Playbook, PlaybookExecution, PlaybookStatus
from app.models.risk import Risk, RiskStatus
from app.models.user import User
from app.risk_engine.ranking import risk_level
from app.services import ledger_service, settings_service
from app.services.asset_service import AssetService
from app.services.incident_service import IncidentService
from app.services.risk_service import OPEN_STATUSES, RiskService
from app.utils.net import assert_public_http_url

logger = structlog.get_logger()

PLAYBOOK_DIR = BACKEND_DIR / "playbooks"
LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PlaybookError(Exception):
    """Invalid playbook operation (maps to HTTP 400/404/409)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class StepContext:
    db: AsyncSession
    execution: PlaybookExecution
    risk: Optional[Risk]
    incident: Optional[Incident]
    asset: Optional[Asset]
    actor: str
    params: Dict[str, Any]


def _normalise_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for i, s in enumerate(sorted(steps, key=lambda x: x.get("order", 0)), start=1):
        s = dict(s)
        s["order"] = i
        s.setdefault("description", "")
        s.setdefault("required", True)
        s.setdefault("on_failure", "stop")
        s.setdefault("timeout_minutes", 15)
        out.append(s)
    return out


class PlaybookService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------ definitions
    async def sync_from_files(self) -> int:
        count = 0
        for path in sorted(PLAYBOOK_DIR.glob("*.json")):
            spec = json.loads(path.read_text(encoding="utf-8"))
            slug = spec.get("id") or path.stem
            steps = _normalise_steps(spec["steps"])
            pb = (await self.db.execute(select(Playbook).where(Playbook.slug == slug))).scalar_one_or_none()
            fields = dict(
                name=spec["name"], description=spec.get("description"), category=spec.get("category", "general"),
                version=spec.get("version", "1.0"), severity_threshold=spec.get("severity_threshold", "medium"),
                steps=steps, trigger_conditions=spec.get("trigger_conditions", {}),
                estimated_duration=max(1, sum(s.get("timeout_minutes", 0) for s in steps)),
            )
            if pb is None:
                pb = Playbook(slug=slug, is_active=True, is_automated=False, required_permissions=[], **fields)
                self.db.add(pb)
            elif pb.version != fields["version"]:
                for k, v in fields.items():
                    setattr(pb, k, v)
            count += 1
        await self.db.flush()
        return count

    async def get(self, ident: str | UUID) -> Optional[Playbook]:
        try:
            uid = ident if isinstance(ident, UUID) else UUID(str(ident))
            cond = Playbook.id == uid
        except ValueError:
            cond = Playbook.slug == str(ident)
        return (await self.db.execute(select(Playbook).where(cond))).scalar_one_or_none()

    async def list(self, active_only: bool = False, category: Optional[str] = None) -> List[Playbook]:
        q = select(Playbook)
        if active_only:
            q = q.where(Playbook.is_active == True)  # noqa: E712
        if category:
            q = q.where(Playbook.category == category)
        return list((await self.db.execute(q.order_by(Playbook.name))).scalars().all())

    async def create(self, data: Dict[str, Any]) -> Playbook:
        slug = data.get("slug") or "-".join(data["name"].lower().split())[:100]
        if (await self.db.execute(select(Playbook).where(or_(Playbook.slug == slug, Playbook.name == data["name"])))).scalar_one_or_none():
            raise PlaybookError("A playbook with this name/slug already exists", 409)
        steps = _normalise_steps(data["steps"])
        pb = Playbook(
            slug=slug, name=data["name"], description=data.get("description"), category=data.get("category", "general"),
            version=data.get("version", "1.0"), severity_threshold=data.get("severity_threshold", "medium"),
            steps=steps, trigger_conditions=data.get("trigger_conditions", {}), is_active=data.get("is_active", True),
            is_automated=False, required_permissions=[],
            estimated_duration=max(1, sum(s.get("timeout_minutes", 0) for s in steps)),
        )
        self.db.add(pb)
        await self.db.flush()
        return pb

    async def update(self, pb: Playbook, data: Dict[str, Any]) -> Playbook:
        if "steps" in data and data["steps"] is not None:
            data["steps"] = _normalise_steps(data["steps"])
            data["estimated_duration"] = max(1, sum(s.get("timeout_minutes", 0) for s in data["steps"]))
        for k, v in data.items():
            setattr(pb, k, v)
        await self.db.flush()
        return pb

    @staticmethod
    def serialize(pb: Playbook) -> Dict[str, Any]:
        steps = pb.steps or []
        return {
            "id": pb.id, "slug": pb.slug, "name": pb.name, "description": pb.description,
            "category": pb.category or "general", "version": pb.version or "1.0",
            "severity_threshold": pb.severity_threshold or "medium", "steps": steps,
            "trigger_conditions": pb.trigger_conditions or {}, "is_active": bool(pb.is_active),
            "estimated_duration": pb.estimated_duration or 0,
            "manual_steps": sum(1 for s in steps if s.get("action_type") == "manual"),
            "automated_steps": sum(1 for s in steps if s.get("action_type") == "automated"),
            "created_at": pb.created_at, "updated_at": pb.updated_at,
        }

    # --------------------------------------------------------- recommendation
    async def recommend(self, risk: Risk, limit: int = 3) -> List[Tuple[Playbook, int, List[str]]]:
        text = " ".join(filter(None, [risk.title, risk.description, risk.cve.description if risk.cve else ""])).lower()
        level = risk_level(risk.bwvs_score or 0)
        scored = []
        for pb in await self.list(active_only=True):
            cond = pb.trigger_conditions or {}
            score, reasons = 0, []
            if risk.category and risk.category in cond.get("categories", []):
                score += 4
                reasons.append(f"matches category '{risk.category}'")
            if cond.get("requires_cve") and risk.cve_id:
                score += 3
                reasons.append("risk is tied to a CVE")
            elif cond.get("requires_cve") and not risk.cve_id:
                continue
            hits = [k for k in cond.get("keywords", []) if k in text]
            if hits:
                score += min(6, 2 * len(hits))
                reasons.append("keywords: " + ", ".join(hits[:3]))
            if score == 0:
                continue
            if LEVEL_RANK[level] >= LEVEL_RANK.get(pb.severity_threshold or "medium", 1):
                score += 1
                reasons.append(f"severity {level} meets threshold")
            scored.append((pb, score, reasons))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:limit]

    # -------------------------------------------------------------- executions
    async def get_execution(self, exec_id: str | UUID) -> Optional[PlaybookExecution]:
        try:
            eid = exec_id if isinstance(exec_id, UUID) else UUID(str(exec_id))
        except ValueError:
            return None
        return (await self.db.execute(select(PlaybookExecution).where(PlaybookExecution.id == eid))).scalar_one_or_none()

    async def list_executions(
        self, page: int = 1, page_size: int = 50, status: Optional[PlaybookStatus] = None,
        risk_id: Optional[UUID] = None, incident_id: Optional[UUID] = None, playbook_id: Optional[UUID] = None,
    ) -> Tuple[List[PlaybookExecution], int]:
        q, cq = select(PlaybookExecution), select(func.count(PlaybookExecution.id))
        for cond in (
            PlaybookExecution.status == status if status else None,
            PlaybookExecution.risk_id == risk_id if risk_id else None,
            PlaybookExecution.incident_id == incident_id if incident_id else None,
            PlaybookExecution.playbook_id == playbook_id if playbook_id else None,
        ):
            if cond is not None:
                q, cq = q.where(cond), cq.where(cond)
        total = (await self.db.execute(cq)).scalar() or 0
        rows = (await self.db.execute(q.order_by(PlaybookExecution.created_at.desc()).offset((page - 1) * page_size).limit(page_size))).scalars().all()
        return list(rows), total

    async def serialize_execution(self, ex: PlaybookExecution) -> Dict[str, Any]:
        pb = await self.get(ex.playbook_id)
        risk_title = None
        if ex.risk_id:
            risk_title = (await self.db.execute(select(Risk.title).where(Risk.id == ex.risk_id))).scalar_one_or_none()
        steps = ex.step_results or []
        done = sum(1 for s in steps if s.get("status") in ("completed", "skipped"))
        return {
            "id": ex.id, "playbook_id": ex.playbook_id, "playbook_name": pb.name if pb else None,
            "playbook_slug": pb.slug if pb else None, "risk_id": ex.risk_id, "risk_title": risk_title,
            "incident_id": ex.incident_id, "status": ex.status, "executed_by": ex.executed_by,
            "started_at": ex.started_at, "completed_at": ex.completed_at, "step_results": steps,
            "progress": round(done / len(steps), 3) if steps else 0.0, "error_message": ex.error_message,
            "output": ex.output or {}, "created_at": ex.created_at,
        }

    async def start(
        self, playbook: Playbook, user: User, risk: Optional[Risk] = None, incident: Optional[Incident] = None,
        resolve_risk: bool = True, params: Optional[Dict[str, Any]] = None,
    ) -> PlaybookExecution:
        if not playbook.is_active:
            raise PlaybookError("Playbook is disabled", 409)
        if incident is None and risk is not None:
            incident = (
                await self.db.execute(select(Incident).where(Incident.risk_id == risk.id).order_by(Incident.created_at.desc()).limit(1))
            ).scalars().first()
        if risk is None and incident is not None and incident.risk_id:
            risk = await RiskService(self.db).get(incident.risk_id)
        if risk is not None:
            running = (
                await self.db.execute(
                    select(PlaybookExecution).where(
                        PlaybookExecution.risk_id == risk.id, PlaybookExecution.playbook_id == playbook.id,
                        PlaybookExecution.status == PlaybookStatus.RUNNING,
                    )
                )
            ).scalars().first()
            if running:
                raise PlaybookError("This playbook is already running for the selected risk", 409)

        steps = [
            {**copy.deepcopy(s), "status": "pending", "started_at": None, "completed_at": None,
             "output": None, "error": None, "completed_by": None, "notes": None}
            for s in playbook.steps
        ]
        ex = PlaybookExecution(
            playbook_id=playbook.id, risk_id=risk.id if risk else None, incident_id=incident.id if incident else None,
            executed_by=user.id, status=PlaybookStatus.PENDING, step_results=steps,
            output={"resolve_risk": resolve_risk, "parameters": params or {}},
        )
        self.db.add(ex)
        await self.db.flush()
        ex.start()
        await ledger_service.safe_record(
            LedgerEventTypes.PLAYBOOK_TRIGGERED, actor=user.email, resource_type="playbook_execution",
            resource_id=str(ex.id),
            data={"playbook": playbook.slug, "risk_id": str(risk.id) if risk else None,
                  "incident_id": str(incident.id) if incident else None},
        )
        if incident is not None:
            incident.add_timeline_event(f"Playbook started: {playbook.name}", None, user.email)
        if risk is not None and risk.status == RiskStatus.ACTIVE:
            risk.status = RiskStatus.MITIGATING
        await self.db.flush()
        await self._advance(ex, user.email, risk, incident)
        return ex

    async def _context(self, ex: PlaybookExecution, actor: str, risk, incident) -> StepContext:
        asset = None
        if risk is not None and risk.asset is not None:
            asset = risk.asset
        elif incident is not None and incident.affected_assets:
            asset = await AssetService(self.db).get(incident.affected_assets[0])
        return StepContext(self.db, ex, risk, incident, asset, actor, (ex.output or {}).get("parameters", {}))

    async def _advance(self, ex: PlaybookExecution, actor: str, risk: Optional[Risk], incident: Optional[Incident]) -> None:
        ctx = await self._context(ex, actor, risk, incident)
        steps = copy.deepcopy(ex.step_results or [])
        while True:
            step = next((s for s in steps if s["status"] == "pending"), None)
            if step is None:
                break
            if step["action_type"] == "manual":
                step["status"] = "awaiting"
                step["started_at"] = datetime.utcnow().isoformat()
                break
            step["started_at"] = datetime.utcnow().isoformat()
            handler = ACTIONS.get(step.get("action") or "")
            try:
                if handler is None:
                    raise PlaybookError(f"Unsupported action '{step.get('action')}'")
                step["output"] = await handler(ctx, step)
                step["status"] = "completed"
            except Exception as exc:
                step["status"] = "failed"
                step["error"] = str(exc)[:500]
                logger.warning("Playbook step failed", step=step["name"], error=str(exc))
            step["completed_at"] = datetime.utcnow().isoformat()
            step["completed_by"] = "system"
            await ledger_service.safe_record(
                LedgerEventTypes.PLAYBOOK_STEP_COMPLETED, actor="system", resource_type="playbook_execution",
                resource_id=str(ex.id), data={"step": step["name"], "status": step["status"], "action": step.get("action")},
            )
            if step["status"] == "failed" and step.get("on_failure", "stop") == "stop":
                break
        ex.step_results = steps
        await self._finalise_if_done(ex, actor, risk, incident)
        await self.db.flush()

    async def _finalise_if_done(self, ex: PlaybookExecution, actor: str, risk: Optional[Risk], incident: Optional[Incident]):
        steps = ex.step_results or []
        failed_stop = next((s for s in steps if s["status"] == "failed" and s.get("on_failure", "stop") == "stop"), None)
        unfinished = [s for s in steps if s["status"] in ("pending", "awaiting")]
        if failed_stop:
            ex.fail(f"Step '{failed_stop['name']}' failed: {failed_stop.get('error')}")
            ex.step_results = steps
        elif not unfinished:
            ex.complete({
                "steps_completed": sum(1 for s in steps if s["status"] == "completed"),
                "steps_skipped": sum(1 for s in steps if s["status"] == "skipped"),
                "total_steps": len(steps),
                "resolve_risk": (ex.output or {}).get("resolve_risk", True),
                "parameters": (ex.output or {}).get("parameters", {}),
            })
            if risk is not None and (ex.output or {}).get("resolve_risk", True):
                await RiskService(self.db).set_status(risk, RiskStatus.RESOLVED)
                await ledger_service.safe_record(
                    LedgerEventTypes.RISK_STATUS_CHANGED, actor=actor, resource_type="risk", resource_id=str(risk.id),
                    data={"status": "resolved", "via": "playbook", "execution": str(ex.id)},
                )
            if incident is not None:
                incident.add_timeline_event("Playbook completed", None, actor)
            await ledger_service.safe_record(
                LedgerEventTypes.PLAYBOOK_COMPLETED, actor=actor, resource_type="playbook_execution",
                resource_id=str(ex.id), data={"status": "completed"},
            )
        else:
            return
        await self.db.flush()

    async def _load_for_action(self, ex: PlaybookExecution):
        risk = await RiskService(self.db).get(ex.risk_id) if ex.risk_id else None
        incident = await IncidentService(self.db).get(ex.incident_id) if ex.incident_id else None
        return risk, incident

    async def complete_step(self, ex: PlaybookExecution, order: int, user: User, notes: Optional[str], skip: bool = False) -> PlaybookExecution:
        if ex.status != PlaybookStatus.RUNNING:
            raise PlaybookError("Execution is not running", 409)
        steps = copy.deepcopy(ex.step_results or [])
        step = next((s for s in steps if s["order"] == order), None)
        if step is None:
            raise PlaybookError("Step not found", 404)
        if step["status"] != "awaiting":
            raise PlaybookError("Only the step currently awaiting an analyst can be completed", 409)
        if skip and step.get("required", True):
            raise PlaybookError("Required steps cannot be skipped", 409)

        risk, incident = await self._load_for_action(ex)
        step["status"] = "skipped" if skip else "completed"
        step["completed_at"] = datetime.utcnow().isoformat()
        step["completed_by"] = user.email
        step["notes"] = notes
        if not skip and step.get("on_complete"):
            handler = ACTIONS.get(step["on_complete"])
            if handler:
                ctx = await self._context(ex, user.email, risk, incident)
                try:
                    step["output"] = await handler(ctx, step)
                except Exception as exc:
                    step["error"] = f"on-complete action failed: {exc}"[:500]
        ex.step_results = steps
        await ledger_service.safe_record(
            LedgerEventTypes.PLAYBOOK_STEP_COMPLETED, actor=user.email, resource_type="playbook_execution",
            resource_id=str(ex.id), data={"step": step["name"], "status": step["status"], "notes": notes},
        )
        if incident is not None:
            incident.add_timeline_event(f"Playbook step {step['status']}: {step['name']}", notes, user.email)
        await self.db.flush()
        await self._advance(ex, user.email, risk, incident)
        return ex

    async def cancel(self, ex: PlaybookExecution, user: User) -> PlaybookExecution:
        if ex.status != PlaybookStatus.RUNNING:
            raise PlaybookError("Execution is not running", 409)
        ex.status = PlaybookStatus.CANCELLED
        ex.completed_at = datetime.utcnow()
        await ledger_service.safe_record(
            LedgerEventTypes.ACTION_TAKEN, actor=user.email, resource_type="playbook_execution",
            resource_id=str(ex.id), data={"action": "cancelled"},
        )
        await self.db.flush()
        return ex


# ============================================================ action handlers
def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


async def _post_webhook(url: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    if not url:
        return False, "not configured"
    try:
        await assert_public_http_url(url)
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        return True, f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, str(exc)[:200]


async def _act_isolate(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    if ctx.asset is None:
        raise PlaybookError("No asset is linked to this risk/incident, so there is nothing to isolate")
    await AssetService(ctx.db).set_isolation(ctx.asset, True)
    hook = (await settings_service.get_setting(ctx.db, "integrations")).get("containment_webhook_url", "")
    delivered, detail = await _post_webhook(hook, {
        "action": "isolate_asset", "asset": ctx.asset.name, "hostname": ctx.asset.hostname,
        "ip_address": ctx.asset.ip_address, "requested_by": ctx.actor,
    })
    await ledger_service.safe_record(
        LedgerEventTypes.ASSET_ISOLATED, actor=ctx.actor, resource_type="asset", resource_id=str(ctx.asset.id),
        data={"asset": ctx.asset.name, "webhook_delivered": delivered},
    )
    return {
        "asset": ctx.asset.name, "isolated": True, "platform_state": "asset removed from digital twin network",
        "containment_webhook": {"configured": bool(hook), "delivered": delivered, "detail": detail},
    }


async def _act_restore(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    if ctx.asset is None or not ctx.asset.is_isolated:
        return {"restored": False, "detail": "asset was not isolated"}
    await AssetService(ctx.db).set_isolation(ctx.asset, False)
    await ledger_service.safe_record(
        LedgerEventTypes.ASSET_RESTORED, actor=ctx.actor, resource_type="asset", resource_id=str(ctx.asset.id),
        data={"asset": ctx.asset.name},
    )
    return {"asset": ctx.asset.name, "restored": True}


async def _act_collect_evidence(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    from app.agents.evidence import build_evidence, evidence_hash

    evidence = await build_evidence(ctx.db, risk=ctx.risk, incident=ctx.incident)
    digest = evidence_hash(evidence)
    await ledger_service.safe_record(
        LedgerEventTypes.EVIDENCE_COLLECTED, actor=ctx.actor, resource_type="playbook_execution",
        resource_id=str(ctx.execution.id), data={"sha256": digest, "events": len(evidence.get("recent_events", []))},
    )
    return {
        "sha256": digest, "collected_at": datetime.utcnow().isoformat(),
        "events_captured": len(evidence.get("recent_events", [])),
        "indicators": evidence.get("indicators", {}),
        "stored_in_ledger": True,
    }


async def _act_block_iocs(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    found: Dict[str, List[str]] = {"ip": [], "domain": [], "hash": []}
    if ctx.incident and ctx.incident.iocs:
        for key, kind in (("ips", "ip"), ("domains", "domain"), ("hashes", "hash")):
            found[kind].extend(ctx.incident.iocs.get(key, []) or [])
    if ctx.asset is not None:
        rows = await ctx.db.execute(
            select(SecurityLog).where(
                SecurityLog.asset_id == ctx.asset.id,
                SecurityLog.severity.in_([LogSeverity.MEDIUM, LogSeverity.HIGH, LogSeverity.CRITICAL]),
            ).order_by(SecurityLog.created_at.desc()).limit(200)
        )
        for log in rows.scalars().all():
            if log.source_ip:
                found["ip"].append(log.source_ip)
            for key, kind in (("ips", "ip"), ("domains", "domain"), ("file_hashes", "hash"), ("hashes", "hash")):
                found[kind].extend((log.indicators or {}).get(key, []) or [])
    blocked, skipped = [], []
    for kind, values in found.items():
        for value in dict.fromkeys(v for v in values if v):
            if kind == "ip" and not _is_public_ip(value):
                skipped.append(value)
                continue
            exists = (
                await ctx.db.execute(select(BlockedIndicator).where(BlockedIndicator.indicator_type == kind, BlockedIndicator.value == value))
            ).scalar_one_or_none()
            if exists:
                continue
            ctx.db.add(BlockedIndicator(
                indicator_type=kind, value=value, created_by=ctx.actor,
                reason=f"Playbook '{ctx.execution.id}'", incident_id=ctx.incident.id if ctx.incident else None,
            ))
            blocked.append(f"{kind}:{value}")
    await ctx.db.flush()
    if not blocked and not skipped:
        raise PlaybookError("No indicators of compromise were found in the incident or related events")
    await ledger_service.safe_record(
        LedgerEventTypes.IOC_BLOCKED, actor=ctx.actor, resource_type="playbook_execution",
        resource_id=str(ctx.execution.id), data={"blocked": blocked[:50], "count": len(blocked)},
    )
    return {"blocked": blocked, "skipped_private_addresses": skipped,
            "blocklist_feed": "/api/v1/blocklist.txt (consumable by firewalls / EDR)"}


async def _act_scan_related(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    if ctx.asset is None:
        raise PlaybookError("No asset is linked to this risk/incident")
    aid = ctx.asset.id
    conns = (
        await ctx.db.execute(
            select(AssetConnection).where(or_(AssetConnection.source_asset_id == aid, AssetConnection.target_asset_id == aid))
        )
    ).scalars().all()
    neighbours = {c.target_asset_id if c.source_asset_id == aid else c.source_asset_id for c in conns}
    # assets that saw the same attacking sources
    ips = [r[0] for r in (await ctx.db.execute(
        select(SecurityLog.source_ip).where(SecurityLog.asset_id == aid, SecurityLog.source_ip != None).distinct().limit(50)  # noqa: E711
    )).all()]
    if ips:
        rows = await ctx.db.execute(
            select(SecurityLog.asset_id).where(SecurityLog.source_ip.in_(ips), SecurityLog.asset_id != None, SecurityLog.asset_id != aid).distinct()  # noqa: E711
        )
        neighbours |= {r[0] for r in rows.all()}
    related = []
    if neighbours:
        assets = (await ctx.db.execute(select(Asset).where(Asset.id.in_(neighbours)))).scalars().all()
        summary = await AssetService(ctx.db).risk_summary([a.id for a in assets])
        for a in assets:
            n, mx = summary.get(a.id, (0, 0.0))
            related.append({"asset": a.name, "criticality": a.criticality.value, "open_risks": n, "max_bwvs": round(mx, 1)})
    related.sort(key=lambda r: r["max_bwvs"], reverse=True)
    return {"origin": ctx.asset.name, "related_assets": related, "count": len(related)}


async def _act_notify(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    subject = (ctx.incident.title if ctx.incident else ctx.risk.title if ctx.risk else "Playbook notification")
    text = f"[Contexta] {subject} - playbook step '{step['name']}' (by {ctx.actor})"
    hook = (await settings_service.get_setting(ctx.db, "integrations")).get("notification_webhook_url", "")
    delivered, detail = await _post_webhook(hook, {"text": text})
    if ctx.incident is not None:
        ctx.incident.add_timeline_event("Notification sent", text if not hook else f"webhook: {detail}", "system")
    await ledger_service.safe_record(
        LedgerEventTypes.ACTION_TAKEN, actor=ctx.actor, resource_type="playbook_execution",
        resource_id=str(ctx.execution.id), data={"action": "notify", "webhook": bool(hook), "delivered": delivered},
    )
    return {"channel": "webhook" if hook else "in_app", "delivered": delivered if hook else True,
            "detail": detail if hook else "recorded on the incident timeline and audit ledger"}


async def _act_run_agents(ctx: StepContext, step: Dict[str, Any]) -> Dict[str, Any]:
    from app.agents.orchestrator import run_discussion

    result = await run_discussion(ctx.db, risk=ctx.risk, incident=ctx.incident, user_id=ctx.execution.executed_by)
    return {"discussion_id": str(result["id"]), "consensus_severity": result["consensus"].get("consensus_severity"),
            "generated_by": result["generated_by"]}


ACTIONS: Dict[str, Callable[[StepContext, Dict[str, Any]], Awaitable[Dict[str, Any]]]] = {
    "isolate_asset": _act_isolate,
    "restore_asset": _act_restore,
    "collect_evidence": _act_collect_evidence,
    "block_iocs": _act_block_iocs,
    "scan_related_hosts": _act_scan_related,
    "notify": _act_notify,
    "run_agent_analysis": _act_run_agents,
}
