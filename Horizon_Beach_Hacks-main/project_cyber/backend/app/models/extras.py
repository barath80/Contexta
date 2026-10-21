"""
Contexta Backend - Supporting models

Asset connections (digital twin topology), agent discussions, blocked
indicators, background job runs, risk snapshots, settings and reports.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text,
    UniqueConstraint,
)
from sqlalchemy import Uuid as UUID

from app.models.base import BaseModel


class AssetConnection(BaseModel):
    """Directed network/trust relationship between two assets."""

    __tablename__ = "asset_connections"
    __table_args__ = (UniqueConstraint("source_asset_id", "target_asset_id", name="uq_asset_conn"),)

    source_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    connection_type = Column(String(30), default="network")  # network|trust|data_flow
    protocols = Column(JSON, default=list)
    bidirectional = Column(Boolean, default=False)


class AgentDiscussion(BaseModel):
    """A persisted multi-agent discussion about a risk or incident."""

    __tablename__ = "agent_discussions"

    risk_id = Column(UUID(as_uuid=True), ForeignKey("risks.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(500), nullable=False)
    status = Column(String(20), default="running", index=True)  # running|completed|failed
    generated_by = Column(String(80))  # gemini:<model> | rules-engine
    messages = Column(JSON, default=list)
    consensus = Column(JSON, default=dict)
    risk_feedback = Column(JSON, default=dict)
    evidence_hash = Column(String(64))
    duration_ms = Column(Integer)
    error = Column(Text)
    created_by = Column(UUID(as_uuid=True), nullable=True)


class BlockedIndicator(BaseModel):
    """IOC added to the internal blocklist by a playbook or analyst."""

    __tablename__ = "blocked_indicators"
    __table_args__ = (UniqueConstraint("indicator_type", "value", name="uq_indicator"),)

    indicator_type = Column(String(20), nullable=False, index=True)  # ip|domain|hash
    value = Column(String(500), nullable=False, index=True)
    reason = Column(Text)
    incident_id = Column(UUID(as_uuid=True), nullable=True)
    created_by = Column(String(255))
    expires_at = Column(DateTime, nullable=True)


class JobRun(BaseModel):
    """Execution record of a background job."""

    __tablename__ = "job_runs"

    job_id = Column(String(60), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")  # running|success|failed
    detail = Column(JSON, default=dict)


class RiskSnapshot(BaseModel):
    """Point-in-time aggregate of the open risk posture (for trend charts)."""

    __tablename__ = "risk_snapshots"

    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    open_total = Column(Integer, default=0)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    avg_bwvs = Column(Float, default=0.0)
    exposure_lakhs = Column(Float, default=0.0)


class AppSetting(BaseModel):
    """Key/value organisation settings."""

    __tablename__ = "app_settings"

    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(JSON, default=dict)
    updated_by = Column(String(255))


class Report(BaseModel):
    """Generated report (board report, weekly summary...)."""

    __tablename__ = "reports"

    kind = Column(String(40), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    content = Column(Text, nullable=False)  # markdown
    params = Column(JSON, default=dict)
    metrics = Column(JSON, default=dict)
    generated_by = Column(String(80))
    created_by = Column(UUID(as_uuid=True), nullable=True)
