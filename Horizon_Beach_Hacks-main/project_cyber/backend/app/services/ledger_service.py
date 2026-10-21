"""
Contexta Backend - Blockchain Ledger Service

Database-backed, Ed25519-signed hash chain:

    block_hash = SHA256(previous_hash + SHA256(data))

Every call to ``record`` appends in its own short transaction under a process
lock so concurrent requests cannot fork the chain.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal, audit_queue
from app.ledger.signature import fingerprint, load_or_create_key, sign_hash, verify_hash
from app.models.ledger import LedgerBlock

logger = structlog.get_logger()

_lock = asyncio.Lock()
GENESIS_PREV = "0" * 64


def _keys():
    return load_or_create_key(settings.ledger_key_path)


async def _latest(db: AsyncSession) -> Optional[LedgerBlock]:
    res = await db.execute(select(LedgerBlock).order_by(LedgerBlock.block_number.desc()).limit(1))
    return res.scalar_one_or_none()


def _new_genesis() -> LedgerBlock:
    private, public = _keys()
    genesis = LedgerBlock.create_genesis_block()
    genesis.signature = sign_hash(private, genesis.block_hash)
    genesis.public_key_fingerprint = fingerprint(public)
    genesis.timestamp = datetime.utcnow()
    return genesis


async def ensure_genesis() -> None:
    async with _lock:
        async with AsyncSessionLocal() as db:
            if await _latest(db) is None:
                db.add(_new_genesis())
                await db.commit()
                logger.info("Ledger genesis block created")


async def write_block(
    event_type: str,
    actor: str = "system",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Optional[LedgerBlock]:
    """Append an event to the ledger now, in its own committed transaction."""
    private, public = _keys()
    async with _lock:
        async with AsyncSessionLocal() as db:
            latest = await _latest(db)
            if latest is None:
                latest = _new_genesis()
                db.add(latest)
                await db.flush()
            payload = {
                "event_type": event_type,
                "actor": actor,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data or {},
            }
            data_json = json.dumps(payload, sort_keys=True, default=str)
            data_hash, block_hash = LedgerBlock.calculate_hash(latest.block_hash, data_json)
            block = LedgerBlock(
                block_number=latest.block_number + 1,
                previous_hash=latest.block_hash,
                data=data_json,
                data_hash=data_hash,
                block_hash=block_hash,
                action_type=event_type,
                actor=actor,
                resource_type=resource_type,
                resource_id=resource_id,
                timestamp=datetime.utcnow(),
                signature=sign_hash(private, block_hash),
                public_key_fingerprint=fingerprint(public),
            )
            db.add(block)
            await db.commit()
            await db.refresh(block)
            return block


async def record(
    event_type: str,
    actor: str = "system",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Optional[LedgerBlock]:
    """
    Audit an event. Inside an API request the entry is queued and written after
    the request commits; elsewhere (jobs, start-up) it is written immediately.
    """
    queue = audit_queue.get()
    entry = dict(event_type=event_type, actor=actor, resource_type=resource_type, resource_id=resource_id, data=data)
    if queue is not None:
        queue.append(entry)
        return None
    return await write_block(**entry)


async def safe_record(*args, **kwargs) -> Optional[LedgerBlock]:
    """Like ``record`` but never raises (audit must not break the main flow)."""
    try:
        return await record(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Ledger write failed", error=str(exc))
        return None


def _column_mismatches(block: LedgerBlock) -> List[Dict[str, Any]]:
    """The denormalised columns shown in the UI must agree with the hashed payload."""
    try:
        payload = json.loads(block.data)
    except ValueError:
        return [{"block": block.block_number, "issue": "unreadable payload"}]
    if block.block_number == 0 or "event_type" not in payload:  # genesis block has its own shape
        return []
    expected = {
        "action_type": payload.get("event_type"), "actor": payload.get("actor"),
        "resource_type": payload.get("resource_type"), "resource_id": payload.get("resource_id"),
    }
    return [
        {"block": block.block_number, "issue": f"{col} does not match the signed payload"}
        for col, want in expected.items() if getattr(block, col) != want
    ]


async def verify_chain(db: AsyncSession) -> Dict[str, Any]:
    """Verify hashes, linkage and signatures of the entire chain."""
    started = datetime.utcnow()
    _, public = _keys()
    own_fp = fingerprint(public)
    issues: List[Dict[str, Any]] = []
    prev: Optional[LedgerBlock] = None
    count = 0
    rows = (await db.execute(select(LedgerBlock).order_by(LedgerBlock.block_number))).scalars().all()
    for block in rows:
        count += 1
        if prev is None:
            if block.block_number != 0 or block.previous_hash != GENESIS_PREV:
                issues.append({"block": block.block_number, "issue": "invalid genesis block"})
        else:
            if block.block_number != prev.block_number + 1:
                issues.append({"block": block.block_number, "issue": "missing block(s) before this one"})
            if block.previous_hash != prev.block_hash:
                issues.append({"block": block.block_number, "issue": "broken chain link"})
        if not block.verify():
            issues.append({"block": block.block_number, "issue": "hash mismatch (content altered)"})
        else:
            issues.extend(_column_mismatches(block))
        if not block.signature:
            issues.append({"block": block.block_number, "issue": "unsigned block"})
        elif block.public_key_fingerprint == own_fp and not verify_hash(public, block.block_hash, block.signature):
            issues.append({"block": block.block_number, "issue": "invalid signature"})
        prev = block
    return {
        "valid": not issues,
        "blocks_verified": count,
        "issues": issues,
        "head_hash": prev.block_hash if prev else None,
        "verified_at": datetime.utcnow().isoformat(),
        "verification_ms": int((datetime.utcnow() - started).total_seconds() * 1000),
    }


async def list_blocks(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    resource_id: Optional[str] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    query = select(LedgerBlock)
    count_q = select(func.count(LedgerBlock.id))
    conds = [
        (LedgerBlock.action_type == event_type) if event_type else None,
        (LedgerBlock.actor == actor) if actor else None,
        (LedgerBlock.resource_id == resource_id) if resource_id else None,
        LedgerBlock.data.ilike(f"%{q}%") if q else None,
    ]
    for cond in conds:
        if cond is not None:
            query = query.where(cond)
            count_q = count_q.where(cond)
    total = (await db.execute(count_q)).scalar() or 0
    rows = (
        await db.execute(query.order_by(LedgerBlock.block_number.desc()).offset(skip).limit(limit))
    ).scalars().all()
    return {"total": total, "blocks": list(rows), "skip": skip, "limit": limit}


async def stats(db: AsyncSession) -> Dict[str, Any]:
    total = (await db.execute(select(func.count(LedgerBlock.id)))).scalar() or 0
    by_type = (
        await db.execute(
            select(LedgerBlock.action_type, func.count(LedgerBlock.id)).group_by(LedgerBlock.action_type)
        )
    ).all()
    head = await _latest(db)
    first = (
        await db.execute(select(LedgerBlock).order_by(LedgerBlock.block_number).limit(1))
    ).scalar_one_or_none()
    return {
        "total_blocks": total,
        "events_by_type": {t: c for t, c in by_type},
        "head_block": head.block_number if head else None,
        "head_hash": head.block_hash if head else None,
        "genesis_timestamp": first.timestamp.isoformat() if first else None,
        "latest_timestamp": head.timestamp.isoformat() if head else None,
    }
