"""
Contexta Backend - Risk Ranking Engine

    Priority = BWVS x Freshness x TrendFactor

Freshness  = 0.5 ** (age_days / 7)           (half-life of 7 days)
TrendFactor in [1.0, 2.0]                    (velocity of spread / exploitation)

Age is measured from the last time *new evidence* was observed for the risk
(first detection, a new correlated security event, or a new exploitation
signal), so actively exploited risks stay on top while stale ones decay.
"""

from datetime import datetime
from typing import Optional

HALF_LIFE_DAYS = 7.0


def risk_level(bwvs: float) -> str:
    """Map a BWVS score to its risk level."""
    if bwvs >= 80:
        return "critical"
    if bwvs >= 60:
        return "high"
    if bwvs >= 40:
        return "medium"
    return "low"


def calculate_freshness(evidence_at: datetime, now: Optional[datetime] = None) -> float:
    now = now or datetime.utcnow()
    age_days = max(0.0, (now - evidence_at).total_seconds() / 86400.0)
    return round(0.5 ** (age_days / HALF_LIFE_DAYS), 4)


def calculate_trend_factor(
    *,
    cisa_kev: bool = False,
    ransomware_use: bool = False,
    has_public_exploit: bool = False,
    epss: Optional[float] = None,
    events_recent: int = 0,
    events_previous: int = 0,
) -> float:
    """
    Trend factor between 1.0 (stable/declining) and 2.0 (rapidly spreading,
    actively exploited).

    Signals (additive, capped at 2.0):
      +0.40  listed in CISA KEV (confirmed in-the-wild exploitation)
      +0.15  KEV entry with known ransomware campaign use
      +0.10  public exploit code available
      +0.30  EPSS (probability of exploitation in next 30 days) scaled by 0.3 x epss
      +0.05..0.30  security events against the asset are increasing
                   (last 24h versus the previous 24h)
    """
    factor = 1.0
    if cisa_kev:
        factor += 0.40
    if ransomware_use:
        factor += 0.15
    if has_public_exploit:
        factor += 0.10
    if epss:
        factor += 0.30 * min(1.0, max(0.0, epss))
    if events_recent > events_previous and events_recent > 0:
        growth = (events_recent - events_previous) / max(events_previous, 1)
        factor += min(0.30, 0.05 + 0.05 * growth)
    return round(min(2.0, max(1.0, factor)), 3)


def calculate_priority(bwvs: float, freshness: float, trend: float) -> float:
    return round(bwvs * freshness * trend, 2)
