"""
Contexta Backend - Audit ledger routes
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_user, require_admin
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.ledger.signature import fingerprint, load_or_create_key, public_key_pem
from app.config import settings
from app.models.ledger import LedgerBlock
from app.models.user import User
from app.services import ledger_service

router = APIRouter()


def _block(b: LedgerBlock) -> Dict[str, Any]:
    try:
        payload = json.loads(b.data)
    except (TypeError, ValueError):
        payload = {"raw": b.data}
    return {
        "block_number": b.block_number, "timestamp": b.timestamp, "event_type": b.action_type, "actor": b.actor,
        "resource_type": b.resource_type, "resource_id": b.resource_id, "data": payload.get("data", payload),
        "previous_hash": b.previous_hash, "data_hash": b.data_hash, "block_hash": b.block_hash,
        "signed": bool(b.signature), "signature": b.signature, "key_fingerprint": b.public_key_fingerprint,
    }


@router.get("", response_model=Dict[str, Any])
async def info(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _, public = load_or_create_key(settings.ledger_key_path)
    return {**await ledger_service.stats(db), "signing_key_fingerprint": fingerprint(public)}


@router.get("/public-key")
async def public_key(_: User = Depends(get_current_user)):
    """Ed25519 public key that verifies block signatures (for independent audit)."""
    _, public = load_or_create_key(settings.ledger_key_path)
    return {"algorithm": "Ed25519", "fingerprint": fingerprint(public), "public_key_pem": public_key_pem(public)}


@router.get("/blocks", response_model=Dict[str, Any])
async def blocks(
    skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), event_type: Optional[str] = None,
    actor: Optional[str] = None, resource_id: Optional[str] = None, q: Optional[str] = Query(None, max_length=100),
    _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    res = await ledger_service.list_blocks(db, skip, limit, event_type, actor, resource_id, q)
    return {"total": res["total"], "skip": skip, "limit": limit, "blocks": [_block(b) for b in res["blocks"]]}


@router.get("/blocks/{block_number}", response_model=Dict[str, Any])
async def block(block_number: int, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    b = (await db.execute(select(LedgerBlock).where(LedgerBlock.block_number == block_number))).scalar_one_or_none()
    if b is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Block not found")
    return _block(b)


@router.get("/verify", response_model=Dict[str, Any])
async def verify(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await ledger_service.verify_chain(db)
    await ledger_service.record(LedgerEventTypes.INTEGRITY_CHECK, actor=user.email,
                                data={"valid": result["valid"], "blocks": result["blocks_verified"], "manual": True})
    return result


@router.get("/export", response_model=Dict[str, Any])
async def export(user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(LedgerBlock).order_by(LedgerBlock.block_number))).scalars().all()
    _, public = load_or_create_key(settings.ledger_key_path)
    await ledger_service.record(LedgerEventTypes.DATA_EXPORTED, actor=user.email, data={"export": "ledger", "blocks": len(rows)})
    return {"exported_at": datetime.utcnow().isoformat(), "public_key_pem": public_key_pem(public),
            "blocks": [_block(b) for b in rows]}
