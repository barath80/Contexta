"""
Contexta Backend - Security Log / Alert Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.log import LogCategory, LogSeverity


class SecurityEventIn(BaseModel):
    """One event pushed by a SIEM / log shipper."""

    source: str = Field(..., min_length=1, max_length=100)
    category: LogCategory
    severity: LogSeverity
    message: str = Field(..., min_length=1, max_length=4000)
    source_ip: Optional[str] = Field(default=None, max_length=45)
    destination_ip: Optional[str] = Field(default=None, max_length=45)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    username: Optional[str] = Field(default=None, max_length=100)
    hostname: Optional[str] = Field(default=None, max_length=255, description="Used to resolve the asset")
    asset_id: Optional[UUID] = None
    occurred_at: Optional[datetime] = None
    raw_log: Dict[str, Any] = Field(default_factory=dict)
    indicators: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    events: List[SecurityEventIn] = Field(min_length=1, max_length=1000)


class IngestResult(BaseModel):
    ingested: int
    matched_to_assets: int
    risks_created: int
    risks_updated: int


class AlertResponse(BaseModel):
    id: UUID
    source: str
    category: str
    severity: str
    message: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    asset_id: Optional[UUID] = None
    asset_name: Optional[str] = None
    status: str
    is_simulated: bool = False
    indicators: Dict[str, Any] = Field(default_factory=dict)
    raw_log: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total: int
    page: int
    page_size: int
    unread: int = 0
