"""
Contexta Backend - Background scheduler

Every job runs in its own session, records a JobRun row (visible in
Settings -> System) and never takes the API down when it fails.
"""

import asyncio
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.ledger.chain import LedgerEventTypes
from app.models.asset import Asset
from app.models.extras import JobRun

logger = structlog.get_logger()

_scheduler: Optional[AsyncIOScheduler] = None
_running: Dict[str, bool] = {}

JobFn = Callable[[Any], Awaitable[Dict[str, Any]]]


# ---------------------------------------------------------------------- jobs
async def job_feed_sync(db) -> Dict[str, Any]:
    from app.services.feed_service import sync_feeds

    return await sync_feeds(db)


async def job_risk_refresh(db) -> Dict[str, Any]:
    from app.services.risk_service import RiskService

    return await RiskService(db).refresh_all(commit_every=50)


async def job_ledger_verify(db) -> Dict[str, Any]:
    from app.services import ledger_service

    result = await ledger_service.verify_chain(db)
    await ledger_service.safe_record(
        LedgerEventTypes.INTEGRITY_CHECK, actor="system",
        data={"valid": result["valid"], "blocks": result["blocks_verified"], "issues": result["issues"][:10]},
    )
    if not result["valid"]:
        logger.error("LEDGER INTEGRITY FAILURE", issues=result["issues"][:5])
    return {"valid": result["valid"], "blocks": result["blocks_verified"], "issues": len(result["issues"])}


JOBS: Dict[str, Dict[str, Any]] = {
    "feed_sync": {"name": "Threat feed sync (CISA KEV, NVD, EPSS)", "fn": job_feed_sync},
    "risk_refresh": {"name": "Risk re-scoring and Top-10 ranking", "fn": job_risk_refresh},
    "ledger_verify": {"name": "Audit ledger integrity check", "fn": job_ledger_verify},
}


# --------------------------------------------------------------------- runner
async def run_job(job_id: str) -> Dict[str, Any]:
    """Run a job now, recording its outcome. Safe to call concurrently (skips if running)."""
    spec = JOBS[job_id]
    if _running.get(job_id):
        return {"status": "skipped", "reason": "already running"}
    _running[job_id] = True
    try:
        async with AsyncSessionLocal() as db:
            run = JobRun(job_id=job_id, started_at=datetime.utcnow(), status="running", detail={})
            db.add(run)
            await db.commit()
            try:
                detail = await spec["fn"](db)
                await db.commit()
                run.status = "failed" if detail.get("status") == "failed" else "success"
                run.detail = _jsonable(detail)
            except Exception as exc:
                await db.rollback()
                logger.error("Job failed", job=job_id, error=str(exc))
                run.status, run.detail = "failed", {"error": str(exc)[:500]}
            run.finished_at = datetime.utcnow()
            await db.commit()
            return {"status": run.status, "detail": run.detail}
    finally:
        _running[job_id] = False


def _jsonable(value: Any) -> Any:
    import json

    return json.loads(json.dumps(value, default=str))


# ------------------------------------------------------------------ lifecycle
def setup_scheduler() -> Optional[AsyncIOScheduler]:
    global _scheduler
    if not settings.scheduler_enabled:
        logger.info("Scheduler disabled by configuration")
        return None
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(run_job, IntervalTrigger(hours=settings.cve_fetch_interval_hours), args=["feed_sync"],
                      id="feed_sync", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(run_job, IntervalTrigger(minutes=settings.risk_calculation_interval_minutes), args=["risk_refresh"],
                      id="risk_refresh", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(run_job, CronTrigger(hour=3, minute=0), args=["ledger_verify"],
                      id="ledger_verify", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.start()
    _scheduler = scheduler
    logger.info("Scheduler started", jobs=[j.id for j in scheduler.get_jobs()])
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
    _scheduler = None


async def job_status() -> List[Dict[str, Any]]:
    """Schedule plus the most recent run of each known job."""
    scheduled = {j.id: j for j in (_scheduler.get_jobs() if _scheduler else [])}
    out = []
    async with AsyncSessionLocal() as db:
        for job_id, spec in JOBS.items():
            last = (
                await db.execute(select(JobRun).where(JobRun.job_id == job_id).order_by(JobRun.started_at.desc()).limit(1))
            ).scalar_one_or_none()
            sched = scheduled.get(job_id)
            out.append({
                "id": job_id, "name": spec["name"], "scheduled": sched is not None,
                "enabled": sched is not None,
                "next_run": sched.next_run_time.isoformat() if sched and sched.next_run_time else None,
                "running": bool(_running.get(job_id)),
                "last_run": None if last is None else {
                    "started_at": last.started_at.isoformat(),
                    "finished_at": last.finished_at.isoformat() if last.finished_at else None,
                    "status": last.status, "detail": last.detail,
                },
            })
    return out


def launch_background(job_id: str) -> None:
    """Fire-and-forget a job (used at start-up and from the admin API)."""
    asyncio.get_running_loop().create_task(run_job(job_id))
