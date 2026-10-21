"""
Contexta Backend - Database Module

Async SQLAlchemy engine/session management. SQLite is supported for local
development and tests, PostgreSQL for production.
"""

from contextvars import ContextVar
from typing import AsyncGenerator, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.config import settings

_engine_kwargs: dict = {"echo": settings.debug}

if settings.is_sqlite:
    # SQLite: no pooling options; allow use across the event loop's threads.
    _engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
else:
    _engine_kwargs.update(pool_pre_ping=True, pool_size=10, max_overflow=20)

async_engine = create_async_engine(settings.database_url, **_engine_kwargs)

if settings.is_sqlite:

    @event.listens_for(async_engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver glue
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

Base = declarative_base()


# Per-request queue of audit-ledger entries. Entries are written only after the
# request's transaction commits (so rolled-back work is never audited and the
# ledger never contends with the request's own write lock).
audit_queue: ContextVar[Optional[list]] = ContextVar("audit_queue", default=None)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Request-scoped session. Commits on success, rolls back on error."""
    queue: list = []
    audit_queue.set(queue)
    ok = False
    try:
        async with AsyncSessionLocal() as session:
            try:
                yield session
                await session.commit()
                ok = True
            except Exception:
                await session.rollback()
                raise
    finally:
        audit_queue.set(None)
    if ok and queue:
        from app.services import ledger_service

        for entry in queue:
            await ledger_service.write_block(**entry)


async def init_db() -> None:
    """Create any missing tables (development/test). Production uses Alembic."""
    # Import models so they register on Base.metadata
    import app.models  # noqa: F401

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn) -> None:
    """Dev/test only: databases created by an older build gain new (nullable) columns in place."""
    from sqlalchemy import inspect, text

    insp = inspect(sync_conn)
    for table in Base.metadata.sorted_tables:
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in existing and col.nullable:
                ddl = col.type.compile(dialect=sync_conn.dialect)
                sync_conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}'))


async def close_db() -> None:
    await async_engine.dispose()
