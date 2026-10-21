"""
Contexta Backend - Playbook Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.playbook import PlaybookStatus


class PlaybookStepModel(BaseModel):
    order: int
    name: str
    description: str = ""
    action_type: str = Field(pattern="^(manual|automated)$")
    action: Optional[str] = None
    on_complete: Optional[str] = None
    on_failure: str = Field(default="stop", pattern="^(stop|continue)$")
    timeout_minutes: int = 15
    required: bool = True
    parameters: Dict[str, Any] = Field(default_factory=dict)


class PlaybookCreate(BaseModel):
    slug: Optional[str] = Field(default=None, pattern="^[a-z0-9-]{3,100}$")
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    category: str = "general"
    version: str = "1.0"
    severity_threshold: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    steps: List[PlaybookStepModel] = Field(min_length=1)
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class PlaybookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = None
    version: Optional[str] = None
    severity_threshold: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    steps: Optional[List[PlaybookStepModel]] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class PlaybookResponse(BaseModel):
    id: UUID
    slug: Optional[str] = None
    name: str
    description: Optional[str] = None
    category: str
    version: str = "1.0"
    severity_threshold: str = "medium"
    steps: List[Dict[str, Any]]
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool
    estimated_duration: int
    manual_steps: int = 0
    automated_steps: int = 0
    created_at: datetime
    updated_at: datetime


class PlaybookRecommendation(BaseModel):
    playbook: PlaybookResponse
    score: int
    reasons: List[str]


class ExecutionStart(BaseModel):
    playbook_id: Optional[UUID] = None
    slug: Optional[str] = None
    risk_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    resolve_risk: bool = True
    parameters: Dict[str, Any] = Field(default_factory=dict)


class StepComplete(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=2000)


class ExecutionResponse(BaseModel):
    id: UUID
    playbook_id: UUID
    playbook_name: Optional[str] = None
    playbook_slug: Optional[str] = None
    risk_id: Optional[UUID] = None
    risk_title: Optional[str] = None
    incident_id: Optional[UUID] = None
    status: PlaybookStatus
    executed_by: Optional[UUID] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    step_results: List[Dict[str, Any]]
    progress: float = 0.0
    error_message: Optional[str] = None
    output: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
