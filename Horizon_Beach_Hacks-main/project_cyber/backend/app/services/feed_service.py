"""
Contexta Backend - Threat feed synchronisation

KEV (backbone, always carries vendor/product) -> NVD enrichment for entries
that match the asset inventory -> recent NVD CVEs -> EPSS -> correlation.
Every stage is independent: a failing feed is reported, not fatal.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.ingestion.cve_collector import CVECollector
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.risk import Risk, RiskStatus
from app.services.cve_service import CVEService
from app.services.risk_service import MIN_MATCH_SCORE, RiskService
from app.services.software_matcher import match_asset_versioned

logger = structlog.get_logger()

_sync_lock = asyncio.Lock()


async def sync_feeds(
    db: AsyncSession,
    collector: Optional[CVECollector] = None,
    max_nvd_enrich: Optional[int] = None,
    include_nvd_recent: bool = True,
) -> Dict[str, Any]:
    """Run a full feed synchronisation. Returns a per-stage report."""
    if _sync_lock.locked():
        return {"status": "skipped", "reason": "a sync is already running"}
    async with _sync_lock:
        started = datetime.utcnow()
        max_nvd_enrich = max_nvd_enrich or settings.nvd_enrich_per_sync
        report: Dict[str, Any] = {"status": "success", "stages": {}, "errors": []}
        collector = collector or CVECollector()
        cves = CVEService(db)
        risks = RiskService(db)

        # 1. CISA KEV --------------------------------------------------------
        try:
            kev = await collector.fetch_cisa_kev()
            created = 0
            for item in kev:
                _, is_new = await cves.upsert(item)
                created += int(is_new)
            await db.commit()  # release the write lock before slower network stages
            report["stages"]["cisa_kev"] = {"fetched": len(kev), "new": created}
        except Exception as exc:
            await db.rollback()
            report["errors"].append(f"CISA KEV: {type(exc).__name__}: {exc}")
            logger.error("KEV sync failed", error=str(exc))

        # 2. NVD enrichment for KEV entries that affect our assets -------------
        try:
            assets = list((await db.execute(select(Asset).where(Asset.is_active == True))).scalars().all())  # noqa: E712
            kev_rows = (await db.execute(select(CVE).where(CVE.cisa_kev == True))).scalars().all()  # noqa: E712
            pending = [c for c in kev_rows if not c.is_processed]  # not yet looked up in NVD
            relevant = [
                c for c in pending
                if any((m := match_asset_versioned(c.affected_software or [], c.version_ranges or [], a.software or [], a.os)) and m[0].score >= MIN_MATCH_SCORE for a in assets)
            ][:max_nvd_enrich]
            enriched = 0
            for cve in relevant:
                try:
                    data = await collector.fetch_nvd_cve(cve.cve_id)
                except Exception as exc:
                    report["errors"].append(f"NVD {cve.cve_id}: {type(exc).__name__}: {exc}")
                    break
                if data:
                    data.pop("cisa_kev", None)
                    await cves.upsert(data)
                    enriched += 1
                cve.is_processed = True  # looked up once; NVD simply may not have version data
                await asyncio.sleep(collector._nvd_delay)
            await db.commit()
            report["stages"]["nvd_enrichment"] = {"candidates": len(relevant), "enriched": enriched}
        except Exception as exc:
            await db.rollback()
            report["errors"].append(f"NVD enrichment: {type(exc).__name__}: {exc}")

        # 3. Recent NVD CVEs -------------------------------------------------
        if include_nvd_recent:
            try:
                recent = await collector.fetch_nvd_recent(days_back=settings.nvd_days_back)
                new = 0
                for item in recent:
                    if (item.get("cvss_score") or 0) < settings.nvd_min_cvss:
                        continue
                    item.pop("cisa_kev", None)
                    _, is_new = await cves.upsert(item)
                    new += int(is_new)
                await db.commit()
                report["stages"]["nvd_recent"] = {"fetched": len(recent), "new": new}
            except Exception as exc:
                await db.rollback()
                report["errors"].append(f"NVD recent: {type(exc).__name__}: {exc}")
                logger.error("NVD sync failed", error=str(exc))

        await db.commit()

        # 4. Correlate with the asset inventory -------------------------------
        corr = await risks.correlate_all(commit_every=25)
        report["stages"]["correlation"] = corr
        await db.commit()

        # 5. EPSS for CVEs that currently matter ------------------------------
        try:
            rows = await db.execute(
                select(CVE.cve_id).join(Risk, Risk.cve_id == CVE.id)
                .where(Risk.status.in_((RiskStatus.ACTIVE, RiskStatus.INVESTIGATING, RiskStatus.MITIGATING)))
                .distinct()
            )
            ids: List[str] = [r[0] for r in rows.all()]
            if ids:
                scores = await collector.fetch_epss(ids)
                for cid, vals in scores.items():
                    cve = await cves.get_by_cve_id(cid)
                    if cve:
                        cve.epss_score, cve.epss_percentile = vals["epss"], vals["percentile"]
                await db.commit()
                report["stages"]["epss"] = {"requested": len(ids), "received": len(scores)}
        except Exception as exc:
            await db.rollback()
            report["errors"].append(f"EPSS: {type(exc).__name__}: {exc}")

        # 6. Re-score everything with the fresh intelligence --------------------
        report["stages"]["scoring"] = await risks.refresh_all(commit_every=50)
        await collector.close()

        if report["errors"]:
            report["status"] = "partial" if report["stages"] else "failed"
        report["duration_seconds"] = round((datetime.utcnow() - started).total_seconds(), 1)
        return report
