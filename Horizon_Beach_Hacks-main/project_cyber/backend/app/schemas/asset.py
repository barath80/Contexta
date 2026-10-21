"""
Contexta Backend - Asset Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.asset import AssetCriticality, AssetType, ExposureLevel

ZONES = ("external", "dmz", "internal", "restricted", "cloud")


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    hostname: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    asset_type: AssetType
    os: Optional[str] = Field(default=None, max_length=100)
    software: List[str] = Field(default_factory=list)
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    criticality: AssetCriticality = AssetCriticality.DEV_TEST
    network_zone: str = Field(default="internal", pattern="^(external|dmz|internal|restricted|cloud)$")
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    daily_revenue_impact: float = Field(default=0.0, ge=0, description="INR lakhs per day of downtime")


class AssetCreate(AssetBase):
    asset_metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[AssetType] = None
    os: Optional[str] = None
    software: Optional[List[str]] = None
    exposure_level: Optional[ExposureLevel] = None
    criticality: Optional[AssetCriticality] = None
    network_zone: Optional[str] = Field(default=None, pattern="^(external|dmz|internal|restricted|cloud)$")
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    daily_revenue_impact: Optional[float] = Field(None, ge=0)
    is_active: Optional[bool] = None
    asset_metadata: Optional[Dict[str, Any]] = None


class AssetResponse(AssetBase):
    id: UUID
    is_active: bool
    is_isolated: bool = False
    isolated_at: Optional[datetime] = None
    asset_metadata: Dict[str, Any] = Field(default_factory=dict)
    exposure_score: int
    criticality_score: int
    business_impact_score: int
    open_risks: int = 0
    max_bwvs: float = 0.0
    risk_level: str = "none"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetImport(BaseModel):
    assets: List[AssetCreate] = Field(min_length=1, max_length=2000)


class ConnectionCreate(BaseModel):
    source_asset_id: UUID
    target_asset_id: UUID
    connection_type: str = Field(default="network", pattern="^(network|trust|data_flow)$")
    protocols: List[str] = Field(default_factory=list)
    bidirectional: bool = False


class ConnectionResponse(ConnectionCreate):
    id: UUID

    model_config = {"from_attributes": True}
