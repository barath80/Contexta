"""
Pytest configuration: an isolated SQLite database, ledger key and administrator per test session.
The environment is set before any ``app`` import because settings are read at import time.
"""

import asyncio
import os
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="contexta-tests-")
os.environ.update({
    "APP_ENV": "test",
    "DATABASE_URL": f"sqlite+aiosqlite:///{Path(_TMP, 'test.db').as_posix()}",
    "LEDGER_KEY_PATH": str(Path(_TMP, "ledger.pem")),
    "ADMIN_EMAIL": "admin@example.com",
    "ADMIN_PASSWORD": "Str0ng-Admin-Passw0rd!",
    "SCHEDULER_ENABLED": "false",
    "GEMINI_API_KEY": "",
    "INGEST_API_KEY": "test-ingest-key",
    "RATE_LIMIT_PER_MINUTE": "100000",
    "LOGIN_RATE_LIMIT_PER_MINUTE": "100000",
})

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

ADMIN = {"username": "admin@example.com", "password": "Str0ng-Admin-Passw0rd!"}


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def app():
    from app.bootstrap import bootstrap
    from app.database import async_engine, init_db
    from app.main import app as fastapi_app

    await init_db()
    await bootstrap()
    yield fastapi_app
    await async_engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture(scope="session")
async def admin_headers(client):
    r = await client.post("/api/v1/auth/login", data=ADMIN)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(scope="session")
async def viewer_headers(client, admin_headers):
    r = await client.post("/api/v1/users", headers=admin_headers, json={
        "email": "viewer@example.com", "username": "viewer", "password": "Viewer-Passw0rd-123", "role": "viewer"})
    assert r.status_code == 201, r.text
    login = await client.post("/api/v1/auth/login", data={"username": "viewer@example.com", "password": "Viewer-Passw0rd-123"})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
