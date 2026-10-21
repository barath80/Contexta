"""Security regression tests: authentication, authorisation, token handling, SSRF, throttling, injection."""

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.config import Settings

API = "/api/v1"


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


# --------------------------------------------------------------- tokens
async def test_alg_none_token_is_rejected(client):
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'x', 'type': 'access', 'exp': 9999999999})}."
    assert (await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401


async def test_token_signed_with_wrong_key_is_rejected(client, admin_headers):
    me = (await client.get(f"{API}/auth/me", headers=admin_headers)).json()
    forged = jwt.encode({"sub": me["id"], "type": "access", "ver": 0, "role": "admin",
                         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, "attacker-key-" * 4, algorithm="HS256")
    assert (await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401


async def test_expired_token_is_rejected(client, admin_headers):
    from app.config import settings

    me = (await client.get(f"{API}/auth/me", headers=admin_headers)).json()
    old = jwt.encode({"sub": me["id"], "type": "access", "ver": 0, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
                     settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    assert (await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {old}"})).status_code == 401


async def test_refresh_token_cannot_be_used_as_access_token(client):
    from tests.conftest import ADMIN

    tokens = (await client.post(f"{API}/auth/login", data=ADMIN)).json()
    r = await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"})
    assert r.status_code == 401
    r = await client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401


async def test_logout_revokes_existing_tokens(client, admin_headers):
    await client.post(f"{API}/users", headers=admin_headers, json={
        "email": "temp@example.com", "username": "tempuser", "password": "Temp-Passw0rd-123", "role": "analyst"})
    t = (await client.post(f"{API}/auth/login", data={"username": "temp@example.com", "password": "Temp-Passw0rd-123"})).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert (await client.get(f"{API}/auth/me", headers=h)).status_code == 200
    await client.post(f"{API}/auth/logout", headers=h, json={})
    assert (await client.get(f"{API}/auth/me", headers=h)).status_code == 401
    assert (await client.post(f"{API}/auth/refresh", json={"refresh_token": t["refresh_token"]})).status_code == 401


async def test_disabled_user_is_locked_out_immediately(client, admin_headers):
    u = (await client.post(f"{API}/users", headers=admin_headers, json={
        "email": "gone@example.com", "username": "goneuser", "password": "Gone-Passw0rd-123", "role": "analyst"})).json()
    t = (await client.post(f"{API}/auth/login", data={"username": "gone@example.com", "password": "Gone-Passw0rd-123"})).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    await client.patch(f"{API}/users/{u['id']}", headers=admin_headers, json={"is_active": False})
    assert (await client.get(f"{API}/auth/me", headers=h)).status_code == 401
    assert (await client.post(f"{API}/auth/login", data={"username": "gone@example.com", "password": "Gone-Passw0rd-123"})).status_code == 403


async def test_login_does_not_reveal_whether_account_exists(client):
    a = await client.post(f"{API}/auth/login", data={"username": "admin@example.com", "password": "nope-nope-nope"})
    b = await client.post(f"{API}/auth/login", data={"username": "nobody@example.com", "password": "nope-nope-nope"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


async def test_registration_disabled_by_default(client):
    r = await client.post(f"{API}/auth/register", json={
        "email": "x@example.com", "username": "xuser", "password": "Some-Passw0rd-123"})
    assert r.status_code == 403


async def test_weak_passwords_rejected(client, admin_headers):
    r = await client.post(f"{API}/users", headers=admin_headers, json={
        "email": "weak@example.com", "username": "weakuser", "password": "short", "role": "viewer"})
    assert r.status_code == 422


async def test_password_hash_never_returned(client, admin_headers):
    body = (await client.get(f"{API}/users", headers=admin_headers)).text
    assert "hashed_password" not in body and "$2b$" not in body


# ------------------------------------------------------------- authorization
MUTATIONS = [
    ("POST", "/assets", {"name": "x", "asset_type": "server"}),
    ("POST", "/assets/import", {"assets": [{"name": "x", "asset_type": "server"}]}),
    ("POST", "/risks", {"title": "manual risk"}),
    ("POST", "/incidents", {"title": "manual incident"}),
    ("POST", "/playbooks/executions", {"slug": "x"}),
    ("POST", "/twin/simulate", {"attack_type": "apt"}),
    ("POST", "/reports/board", {}),
    ("POST", "/agents/discussions", {"risk_id": "00000000-0000-0000-0000-000000000000"}),
    ("POST", "/logs/ingest", {"events": [{"source": "s", "category": "anomaly", "severity": "low", "message": "m"}]}),
    ("PUT", "/settings/organization", {"name": "x"}),
    ("PUT", "/settings/integrations", {}),
    ("POST", "/users", {"email": "a@example.com", "username": "aaa", "password": "Aaaaaaaa-1234567"}),
    ("POST", "/settings/jobs/feed_sync/run", {}),
]


@pytest.mark.parametrize("method,path,body", MUTATIONS)
async def test_viewer_cannot_perform_privileged_actions(client, viewer_headers, method, path, body):
    r = await client.request(method, API + path, headers=viewer_headers, json=body)
    assert r.status_code == 403, f"{method} {path} -> {r.status_code}"


@pytest.mark.parametrize("method,path,body", MUTATIONS)
async def test_anonymous_cannot_perform_privileged_actions(client, method, path, body):
    r = await client.request(method, API + path, json=body)
    assert r.status_code == 401, f"{method} {path} -> {r.status_code}"


async def test_analyst_cannot_use_admin_endpoints(client, admin_headers):
    await client.post(f"{API}/users", headers=admin_headers, json={
        "email": "analyst@example.com", "username": "analyst1", "password": "Analyst-Passw0rd-1", "role": "analyst"})
    t = (await client.post(f"{API}/auth/login", data={"username": "analyst@example.com", "password": "Analyst-Passw0rd-1"})).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    for path in ("/users", "/settings/system", "/settings/integrations"):
        assert (await client.get(API + path, headers=h)).status_code == 403
    assert (await client.get(f"{API}/risks/top10", headers=h)).status_code == 200


async def test_admin_cannot_demote_or_disable_self(client, admin_headers):
    me = (await client.get(f"{API}/auth/me", headers=admin_headers)).json()
    assert (await client.patch(f"{API}/users/{me['id']}", headers=admin_headers, json={"role": "viewer"})).status_code == 400
    assert (await client.patch(f"{API}/users/{me['id']}", headers=admin_headers, json={"is_active": False})).status_code == 400


async def test_preferences_cannot_be_used_for_mass_assignment(client, admin_headers):
    r = await client.put(f"{API}/auth/me", headers=admin_headers, json={"preferences": {"theme": "dark", "role": "admin", "evil": "x"}})
    prefs = r.json()["preferences"]
    assert "evil" not in prefs and "role" not in prefs


# ---------------------------------------------------------------------- SSRF
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000/admin", "http://localhost/hook",
    "http://10.0.0.5/hook", "http://[::1]/hook", "http://192.168.1.1/hook",
])
async def test_webhook_to_internal_address_is_refused(client, admin_headers, url):
    r = await client.put(f"{API}/settings/integrations", headers=admin_headers,
                         json={"notification_webhook_url": url, "containment_webhook_url": ""})
    assert r.status_code == 400, f"{url} -> {r.status_code} {r.text}"


async def test_webhook_scheme_must_be_http(client, admin_headers):
    r = await client.put(f"{API}/settings/integrations", headers=admin_headers,
                         json={"notification_webhook_url": "file:///etc/passwd", "containment_webhook_url": ""})
    assert r.status_code == 422


# ------------------------------------------------------- proxy header / throttling
async def test_spoofed_forwarded_for_does_not_bypass_rate_limit(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 3)
    statuses = []
    for i in range(8):
        r = await client.post(f"{API}/auth/login", data={"username": f"spoof{i}@example.com", "password": "x" * 12},
                              headers={"X-Forwarded-For": f"198.51.100.{i}"})
        statuses.append(r.status_code)
    assert 429 in statuses, statuses


async def test_account_throttle_blocks_password_guessing(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 2)  # 6 per 15 min per account
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    codes = []
    for i in range(10):
        r = await client.post(f"{API}/auth/login", data={"username": "victim@example.com", "password": "guess" * 3},
                              headers={"X-Forwarded-For": f"203.0.113.{i}"})
        codes.append(r.status_code)
    assert codes.count(429) >= 3, codes


# ------------------------------------------------------------------ injection
@pytest.mark.parametrize("payload", ["' OR 1=1 --", "%' OR '1'='1", "'; DROP TABLE users; --", "\" OR \"\"=\""])
async def test_sql_injection_strings_are_inert(client, admin_headers, payload):
    for path in ("/search", "/risks", "/assets", "/alerts", "/incidents", "/ledger/blocks"):
        params = {"q": payload}
        r = await client.get(API + path, headers=admin_headers, params=params)
        assert r.status_code in (200, 422), f"{path} -> {r.status_code}"
    assert (await client.get(f"{API}/users", headers=admin_headers)).status_code == 200  # users table intact


async def test_oversized_ingest_batch_rejected(client, admin_headers):
    events = [{"source": "s", "category": "anomaly", "severity": "low", "message": "m"}] * 1001
    assert (await client.post(f"{API}/logs/ingest", headers=admin_headers, json={"events": events})).status_code == 422


async def test_errors_do_not_leak_internals(client, admin_headers):
    r = await client.get(f"{API}/risks/not-a-uuid", headers=admin_headers)
    assert "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()


async def test_security_headers_present(client):
    r = await client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"


# ------------------------------------------------------------ production config
def _prod(**kw):
    base = dict(app_env="production", secret_key="s" * 40, jwt_secret_key="j" * 40, debug=False,
                admin_email="a@example.com", admin_password="A-very-long-password-1")
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_production_rejects_default_secrets():
    with pytest.raises(RuntimeError):
        _prod(secret_key="change-me-in-production").validate_for_runtime()
    with pytest.raises(RuntimeError):
        _prod(jwt_secret_key="short").validate_for_runtime()


def test_production_rejects_debug_wildcard_cors_and_weak_admin_password():
    for kw in (dict(debug=True), dict(cors_origins='["*"]'), dict(admin_password="short-pw")):
        with pytest.raises(RuntimeError):
            _prod(**kw).validate_for_runtime()


def test_production_accepts_good_configuration():
    _prod().validate_for_runtime()
