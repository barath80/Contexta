"""
Contexta Backend - CVE Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class CVEResponse(BaseModel):
    id: UUID
    cve_id: str
    description: str
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    affected_software: List[str] = Field(default_factory=list)
    attack_vector: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    has_exploit: bool = False
    exploit_sources: List[str] = Field(default_factory=list)
    cisa_kev: bool = False
    kev_ransomware_use: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cwes: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    ai_extracted_data: Dict[str, Any] = Field(default_factory=dict)
    exploit_activity_score: int = 0
    open_risks: int = 0

    model_config = {"from_attributes": True}


class CVEListResponse(BaseModel):
    items: List[CVEResponse]
    total: int
    page: int
    page_size: int
