"""End-to-end API tests against a real (temporary) database: auth, RBAC, assets, CVE correlation, ingestion."""

import pytest

API = "/api/v1"


async def test_health(client):
    assert (await client.get("/health")).json()["status"] == "ok"
    assert (await client.get("/health/ready")).json()["database"] == "ok"


async def test_unauthenticated_requests_are_rejected(client):
    assert (await client.get(f"{API}/risks/top10")).status_code == 401
    assert (await client.get(f"{API}/dashboard/overview")).status_code == 401


async def test_login_failure_and_success(client):
    bad = await client.post(f"{API}/auth/login", data={"username": "admin@example.com", "password": "wrong-password"})
    assert bad.status_code == 401
    good = await client.post(f"{API}/auth/login", data={"username": "admin@example.com", "password": "Str0ng-Admin-Passw0rd!"})
    assert good.status_code == 200 and {"access_token", "refresh_token"} <= good.json().keys()
    refreshed = await client.post(f"{API}/auth/refresh", json={"refresh_token": good.json()["refresh_token"]})
    assert refreshed.status_code == 200


async def test_me_returns_profile(client, admin_headers):
    me = (await client.get(f"{API}/auth/me", headers=admin_headers)).json()
    assert me["email"] == "admin@example.com" and me["role"] == "admin"


async def test_viewer_cannot_mutate(client, viewer_headers):
    r = await client.post(f"{API}/assets", headers=viewer_headers, json={"name": "nope", "asset_type": "server"})
    assert r.status_code == 403
    assert (await client.get(f"{API}/assets", headers=viewer_headers)).status_code == 200
    assert (await client.get(f"{API}/users", headers=viewer_headers)).status_code == 403


async def test_asset_lifecycle(client, admin_headers):
    r = await client.post(f"{API}/assets", headers=admin_headers, json={
        "name": "web-01", "asset_type": "server", "hostname": "web-01.example.com", "ip_address": "10.0.0.10",
        "exposure_level": "internet_facing", "criticality": "core_backend", "daily_revenue_impact": 12.5,
        "software": ["nginx 1.18.0"], "network_zone": "dmz"})
    assert r.status_code == 201, r.text
    asset = r.json()
    dup = await client.post(f"{API}/assets", headers=admin_headers, json={"name": "web-01b", "asset_type": "server", "hostname": "web-01.example.com"})
    assert dup.status_code == 409

    upd = await client.patch(f"{API}/assets/{asset['id']}", headers=admin_headers, json={"owner": "platform-team"})
    assert upd.json()["owner"] == "platform-team"

    iso = await client.post(f"{API}/assets/{asset['id']}/isolate", headers=admin_headers, json={})
    assert iso.json()["is_isolated"] is True
    rest = await client.post(f"{API}/assets/{asset['id']}/restore", headers=admin_headers, json={})
    assert rest.json()["is_isolated"] is False

    stats = (await client.get(f"{API}/assets/stats", headers=admin_headers)).json()
    assert stats["total"] >= 1 and stats["internet_facing"] >= 1


async def test_patched_asset_is_not_flagged(client, admin_headers):
    r = await client.post(f"{API}/assets", headers=admin_headers, json={
        "name": "web-patched", "asset_type": "server", "hostname": "web-patched.example.com", "software": ["nginx 1.25.3"]})
    assert r.status_code == 201
    from datetime import datetime

    from app.database import AsyncSessionLocal
    from app.services.cve_service import CVEService
    from app.services.risk_service import RiskService

    async with AsyncSessionLocal() as db:
        await CVEService(db).upsert({
            "cve_id": "CVE-2021-23017", "description": "nginx resolver off-by-one", "cvss_score": 9.8,
            "affected_software": ["nginx:nginx"], "published_date": datetime(2021, 6, 1), "cisa_kev": True,
            "version_ranges": [{"product": "nginx:nginx", "exact": None, "start_incl": "0.6.18", "end_excl": "1.20.1"}],
        })
        await db.commit()
    async with AsyncSessionLocal() as db:
        await RiskService(db).correlate_all()
        await db.commit()
    risks = (await client.get(f"{API}/risks", headers=admin_headers, params={"q": "web-patched"})).json()["items"]
    assert not [x for x in risks if x["cve"] and x["cve"]["cve_id"] == "CVE-2021-23017"]


async def test_cve_correlation_produces_scored_risk(client, admin_headers):
    """A KEV CVE affecting software on an internet-facing, business-critical asset becomes a high-priority risk."""
    from datetime import datetime

    from app.database import AsyncSessionLocal
    from app.services.cve_service import CVEService
    from app.services.risk_service import RiskService

    async with AsyncSessionLocal() as db:
        await CVEService(db).upsert({
            "cve_id": "CVE-2021-23017", "description": "nginx resolver off-by-one", "cvss_score": 9.8,
            "affected_software": ["nginx:nginx"], "published_date": datetime(2021, 6, 1),
            "has_exploit": True, "exploit_sources": ["cisa_kev"], "cisa_kev": True,
            "version_ranges": [{"product": "nginx:nginx", "exact": None, "start_incl": "0.6.18", "end_excl": "1.20.1"}],
        })
        await db.commit()
    async with AsyncSessionLocal() as db:
        result = await RiskService(db).correlate_all()
        await RiskService(db).refresh_all()
        await db.commit()
    assert result["assets"] >= 1  # the risk itself may already exist from an earlier correlation run

    top = (await client.get(f"{API}/risks/top10", headers=admin_headers)).json()["risks"]
    risk = next(r for r in top if r["cve"] and r["cve"]["cve_id"] == "CVE-2021-23017")
    assert risk["level"] in ("critical", "high") and risk["bwvs_score"] > 60
    assert risk["asset"]["name"] == "web-01"
    assert risk["components"]["final_bwvs"] == pytest.approx(risk["bwvs_score"], abs=1.0)

    # incident + playbook workflow on that risk
    inc = await client.post(f"{API}/risks/{risk['id']}/investigate", headers=admin_headers, json={})
    assert inc.status_code == 201 and inc.json()["ref"]
    recs = (await client.get(f"{API}/risks/{risk['id']}/playbooks", headers=admin_headers)).json()
    assert recs, "expected at least one recommended playbook"
    ex = await client.post(f"{API}/playbooks/executions", headers=admin_headers,
                           json={"slug": recs[0]["playbook"]["slug"], "risk_id": risk["id"]})
    assert ex.status_code == 201, ex.text

    overview = (await client.get(f"{API}/dashboard/overview", headers=admin_headers)).json()
    assert overview["open_risks"] >= 1 and overview["has_data"] is True


async def test_event_ingestion_correlates_to_assets(client, admin_headers):
    events = {"events": [{
        "source": "firewall", "category": "brute_force", "severity": "high", "message": "SSH brute force from 203.0.113.50",
        "source_ip": "203.0.113.50", "hostname": "web-01.example.com", "destination_port": 22}]}
    # API-key authentication (machine source)
    r = await client.post(f"{API}/logs/ingest", headers={"X-API-Key": "test-ingest-key"}, json=events)
    assert r.status_code == 202, r.text
    assert r.json()["ingested"] == 1 and r.json()["matched_to_assets"] == 1
    assert (await client.post(f"{API}/logs/ingest", headers={"X-API-Key": "wrong"}, json=events)).status_code == 401

    alerts = (await client.get(f"{API}/alerts", headers=admin_headers, params={"q": "203.0.113.50"})).json()
    assert alerts["total"] == 1 and alerts["items"][0]["asset_name"] == "web-01"
    ack = await client.post(f"{API}/alerts/{alerts['items'][0]['id']}/acknowledge", headers=admin_headers)
    assert ack.json()["status"] == "acknowledged"


async def test_agent_analysis_runs_in_rules_mode(client, admin_headers):
    risks = (await client.get(f"{API}/risks", headers=admin_headers, params={"page_size": 1})).json()["items"]
    assert risks
    r = await client.post(f"{API}/agents/discussions", headers=admin_headers, json={"risk_id": risks[0]["id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["messages"]) == 5 and body["consensus"]["consensus_severity"]


async def test_twin_simulation_uses_inventory(client, admin_headers):
    r = await client.post(f"{API}/twin/simulate", headers=admin_headers, json={"attack_type": "ransomware"})
    assert r.status_code == 200, r.text
    assert r.json()["impact"]["assets_total"] >= 1


async def test_validation_errors_are_structured(client, admin_headers):
    r = await client.post(f"{API}/assets", headers=admin_headers, json={"name": "", "asset_type": "toaster"})
    assert r.status_code == 422 and r.json()["errors"]


async def test_reports_and_executive(client, admin_headers):
    ex = (await client.get(f"{API}/dashboard/executive", headers=admin_headers)).json()
    assert ex["currency"] == "INR lakhs" and ex["assumptions"]
    rep = await client.post(f"{API}/reports/board", headers=admin_headers, json={})
    assert rep.status_code == 201 and "Board Risk Report" in rep.json()["content"]
