"""
Contexta Backend - Incident Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.incident import IncidentSeverity, IncidentStatus


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=500)
    description: Optional[str] = None
    risk_id: Optional[UUID] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    incident_type: str = Field(default="security_incident", max_length=50)
    assigned_to: Optional[str] = None
    affected_assets: List[UUID] = Field(default_factory=list)
    iocs: Dict[str, Any] = Field(default_factory=dict)


class IncidentFromRisk(BaseModel):
    risk_id: UUID
    assigned_to: Optional[str] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=500)
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[str] = None
    affected_assets: Optional[List[UUID]] = None
    iocs: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None


class IncidentNote(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)


class IncidentClose(BaseModel):
    resolution: str = Field(..., min_length=3, max_length=4000)
    resolve_risk: bool = True


class TimelineEvent(BaseModel):
    timestamp: str
    event: str
    details: Optional[str] = None
    actor: Optional[str] = None


class IncidentResponse(BaseModel):
    id: UUID
    ref: Optional[str] = None
    title: str
    description: Optional[str] = None
    incident_type: str = "security_incident"
    risk_id: Optional[UUID] = None
    risk_title: Optional[str] = None
    risk_bwvs: Optional[float] = None
    status: IncidentStatus
    severity: IncidentSeverity
    created_by: Optional[UUID] = None
    assigned_to: Optional[str] = None
    timeline: List[TimelineEvent] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    affected_asset_names: List[str] = Field(default_factory=list)
    iocs: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    items: List[IncidentResponse]
    total: int
    page: int
    page_size: int
