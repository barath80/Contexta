"""
Contexta Backend - Models Package

Importing this package registers every model on Base.metadata.
"""

from app.models.base import BaseModel, TimestampMixin
from app.models.user import User, UserRole
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.log import SecurityLog
from app.models.risk import Risk, RiskScore
from app.models.incident import Incident, IncidentAnalysis
from app.models.ledger import LedgerBlock
from app.models.playbook import Playbook, PlaybookExecution
from app.models.extras import (
    AssetConnection, AgentDiscussion, BlockedIndicator, JobRun,
    RiskSnapshot, AppSetting, Report,
)

__all__ = [
    "BaseModel", "TimestampMixin", "User", "UserRole", "Asset", "CVE", "SecurityLog",
    "Risk", "RiskScore", "Incident", "IncidentAnalysis", "LedgerBlock", "Playbook",
    "PlaybookExecution", "AssetConnection", "AgentDiscussion", "BlockedIndicator",
    "JobRun", "RiskSnapshot", "AppSetting", "Report",
]
