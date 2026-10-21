"""
Contexta Backend - Settings Service

Organisation-wide settings stored in the app_settings table.
"""

from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.extras import AppSetting

DEFAULTS: Dict[str, Dict[str, Any]] = {
    "organization": {
        "name": "",
        "industry": "technology",
        "region": "global",
        "size": "medium",
        "compliance_frameworks": [],
    },
    "integrations": {
        # POST target for SOAR/chat notifications (Slack-compatible JSON).
        "notification_webhook_url": "",
        # POST target invoked for containment actions (isolate_asset).
        "containment_webhook_url": "",
    },
}


async def get_setting(db: AsyncSession, key: str) -> Dict[str, Any]:
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    merged = dict(DEFAULTS.get(key, {}))
    if row and isinstance(row.value, dict):
        merged.update(row.value)
    return merged


async def set_setting(db: AsyncSession, key: str, value: Dict[str, Any], actor: str) -> Dict[str, Any]:
    allowed = set(DEFAULTS.get(key, {}).keys())
    clean = {k: v for k, v in value.items() if not allowed or k in allowed}
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    if row is None:
        row = AppSetting(key=key, value=clean, updated_by=actor)
        db.add(row)
    else:
        row.value = {**(row.value or {}), **clean}
        row.updated_by = actor
    await db.flush()
    return await get_setting(db, key)
