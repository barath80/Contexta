"""Ledger signing and chain verification."""

import pytest

from app.ledger.signature import fingerprint, load_or_create_key, sign_hash, verify_hash


def test_signature_roundtrip_and_tamper_detection(tmp_path):
    private, public = load_or_create_key(str(tmp_path / "k.pem"))
    sig = sign_hash(private, "ab" * 32)
    assert verify_hash(public, "ab" * 32, sig)
    assert not verify_hash(public, "cd" * 32, sig)
    assert len(fingerprint(public)) == 64


def test_key_is_persisted(tmp_path):
    path = str(tmp_path / "k.pem")
    _, first = load_or_create_key(path)
    _, second = load_or_create_key(path)
    assert fingerprint(first) == fingerprint(second)


@pytest.mark.asyncio
async def test_chain_verifies_and_detects_tampering(client, admin_headers):
    from sqlalchemy import update

    from app.database import AsyncSessionLocal
    from app.models.ledger import LedgerBlock

    # Generate some audit entries through the API
    for i in range(3):
        r = await client.post("/api/v1/assets", headers=admin_headers, json={
            "name": f"ledger-asset-{i}", "asset_type": "server", "hostname": f"ledger-{i}.example.com"})
        assert r.status_code == 201, r.text

    ok = (await client.get("/api/v1/ledger/verify", headers=admin_headers)).json()
    assert ok["valid"] is True and ok["blocks_verified"] >= 4

    blocks = (await client.get("/api/v1/ledger/blocks", headers=admin_headers, params={"limit": 200})).json()["blocks"]
    target = next(b for b in blocks if b["event_type"] == "asset_created")
    async with AsyncSessionLocal() as db:
        await db.execute(update(LedgerBlock).where(LedgerBlock.block_number == target["block_number"]).values(actor="mallory"))
        await db.commit()
    bad = (await client.get("/api/v1/ledger/verify", headers=admin_headers)).json()
    assert bad["valid"] is False and bad["issues"]
    # restore so later tests see an intact chain
    async with AsyncSessionLocal() as db:
        await db.execute(update(LedgerBlock).where(LedgerBlock.block_number == target["block_number"]).values(actor=target["actor"]))
        await db.commit()
    assert (await client.get("/api/v1/ledger/verify", headers=admin_headers)).json()["valid"] is True
