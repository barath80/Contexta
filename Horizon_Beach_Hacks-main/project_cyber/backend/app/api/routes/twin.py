"""
Contexta Backend - Digital twin routes (topology, attack paths, simulation)
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_analyst
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.user import User
from app.services import ledger_service, twin_service

router = APIRouter()


class SimulationRequest(BaseModel):
    attack_type: str = Field(pattern="^(ransomware|apt|insider|ddos)$")
    entry_point: Optional[str] = Field(default=None, description="Asset id; defaults to the most exposed internet-facing asset")
    target: Optional[str] = None
    seed: Optional[int] = Field(default=None, description="Fix the random seed for a reproducible run")


@router.get("/attack-types", response_model=List[Dict[str, Any]])
async def attack_types(_: User = Depends(get_current_user)):
    return [{"id": k, "label": v["label"], "method": v["method"], "time_to_impact": v["time_to_impact"],
             "spreads": v["spreads"]} for k, v in twin_service.ATTACKS.items()]


@router.get("/topology", response_model=Dict[str, Any])
async def topology(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await twin_service.topology(db)


@router.get("/critical-paths", response_model=List[Dict[str, Any]])
async def critical_paths(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await twin_service.critical_paths(db)


@router.get("/blast-radius/{asset_id}", response_model=Dict[str, Any])
async def blast_radius(asset_id: str, max_hops: int = Query(3, ge=1, le=8), _: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    res = await twin_service.blast_radius(db, asset_id, max_hops)
    if res is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found in the active network graph (it may be isolated)")
    return res


@router.get("/attack-paths", response_model=List[Dict[str, Any]])
async def attack_paths(start_id: str, target_id: str, algorithm: str = Query("bfs", pattern="^(bfs|dfs)$"),
                       max_depth: int = Query(8, ge=1, le=12), _: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    res = await twin_service.attack_paths(db, start_id, target_id, algorithm, max_depth)
    if res is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found in the active network graph")
    return res


@router.post("/simulate", response_model=Dict[str, Any])
async def simulate(req: SimulationRequest, user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    try:
        result = await twin_service.simulate(db, req.attack_type, req.entry_point, req.target, req.seed)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    await ledger_service.record(LedgerEventTypes.ACTION_TAKEN, actor=user.email, resource_type="simulation",
                                resource_id=result["simulation_id"],
                                data={"attack": req.attack_type, "entry": result["entry_point_name"],
                                      "risk": result["risk_assessment"]})
    return result
