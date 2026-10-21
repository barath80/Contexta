"""
Contexta Backend - Risk Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.risk import RiskStatus


class BWVSComponents(BaseModel):
    cvss_score: float
    exploit_activity: float
    exposure_level: float
    asset_criticality: float
    business_impact: float
    ai_relevance: float
    final_bwvs: float


class RiskCVE(BaseModel):
    id: UUID
    cve_id: str
    cvss_score: float
    severity: Optional[str] = None
    cisa_kev: bool = False
    has_exploit: bool = False
    epss_score: Optional[float] = None
    description: str = ""
    published_date: Optional[datetime] = None


class RiskAsset(BaseModel):
    id: UUID
    name: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: str
    exposure_level: str
    criticality: str
    business_unit: Optional[str] = None
    is_isolated: bool = False


class RiskResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    category: str = "vulnerability"
    source: str = "cve_correlation"
    bwvs_score: float
    priority_score: float
    level: str = Field(description="critical | high | medium | low")
    status: RiskStatus
    ai_relevance_score: float
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)
    freshness_factor: float
    trend_factor: float
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    is_top_10: bool = False
    remediation_notes: Optional[str] = None
    match_reasons: List[str] = Field(default_factory=list)
    affected_assets_count: int = 1
    cve: Optional[RiskCVE] = None
    asset: Optional[RiskAsset] = None
    components: Optional[BWVSComponents] = None
    created_at: datetime
    updated_at: datetime


class TopRisksResponse(BaseModel):
    risks: List[RiskResponse]
    last_calculated: datetime
    calculation_interval_minutes: int


class RiskListResponse(BaseModel):
    items: List[RiskResponse]
    total: int
    page: int
    page_size: int


class RiskStatusUpdate(BaseModel):
    status: RiskStatus
    notes: Optional[str] = Field(default=None, max_length=4000)


class RiskCreate(BaseModel):
    title: str = Field(min_length=3, max_length=500)
    description: Optional[str] = None
    asset_id: Optional[UUID] = None
    cve_id: Optional[str] = Field(default=None, description="CVE identifier, e.g. CVE-2024-3400")
    category: str = "manual"
