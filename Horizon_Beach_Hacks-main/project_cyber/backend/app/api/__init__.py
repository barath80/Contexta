"""
Contexta Backend - API router assembly (mounted at /api/v1).
"""

from fastapi import APIRouter

from app.api.routes import (
    admin, agents, alerts, assets, auth, cves, dashboard, incidents, ledger, playbooks, risks, twin,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(auth.users_router, prefix="/users", tags=["Users"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(dashboard.reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(dashboard.search_router, prefix="/search", tags=["Search"])
api_router.include_router(risks.router, prefix="/risks", tags=["Risk Management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])
api_router.include_router(cves.router, prefix="/cves", tags=["CVE Intelligence"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(alerts.ingest_router, prefix="/logs", tags=["SIEM Ingestion"])
api_router.include_router(agents.router, prefix="/agents", tags=["AI Agents"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["Playbooks"])
api_router.include_router(ledger.router, prefix="/ledger", tags=["Audit Ledger"])
api_router.include_router(twin.router, prefix="/twin", tags=["Digital Twin"])
api_router.include_router(admin.router, prefix="/settings", tags=["Settings & System"])
api_router.include_router(admin.blocklist_router, tags=["Blocklist"])

__all__ = ["api_router"]
