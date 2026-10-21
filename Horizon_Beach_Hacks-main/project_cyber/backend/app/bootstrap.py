"""
Contexta Backend - First-run bootstrap

* creates the administrator from ADMIN_EMAIL / ADMIN_PASSWORD when no user exists
* loads playbook definitions
* creates the ledger genesis block
"""

import structlog
from sqlalchemy import func, select

from app.auth.password import hash_password
from app.config import settings
from app.database import AsyncSessionLocal
from app.ledger.chain import LedgerEventTypes
from app.models.user import User, UserRole
from app.services import ledger_service
from app.services.playbook_service import PlaybookService

logger = structlog.get_logger()


async def bootstrap() -> None:
    await ledger_service.ensure_genesis()

    async with AsyncSessionLocal() as db:
        users = (await db.execute(select(func.count(User.id)))).scalar() or 0
        if users == 0:
            if settings.admin_email and settings.admin_password:
                db.add(User(
                    email=settings.admin_email.lower(), username=settings.admin_email.split("@")[0],
                    hashed_password=hash_password(settings.admin_password), full_name=settings.admin_full_name,
                    role=UserRole.ADMIN, is_active=True, is_verified=True, preferences={},
                ))
                await db.commit()
                await ledger_service.safe_record(LedgerEventTypes.USER_CREATED, actor="system",
                                                 data={"email": settings.admin_email, "role": "admin", "via": "bootstrap"})
                logger.info("Bootstrap administrator created", email=settings.admin_email)
            else:
                logger.warning(
                    "No users exist and ADMIN_EMAIL/ADMIN_PASSWORD are not set - nobody can sign in. "
                    "Set them in .env and restart."
                )

    async with AsyncSessionLocal() as db:
        n = await PlaybookService(db).sync_from_files()
        await db.commit()
        logger.info("Playbooks loaded", count=n)
