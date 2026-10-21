# Contexta API reference

Base URL: `/api/v1` (interactive docs at `/docs` when `APP_ENV` is not `production`).

**Authentication** — `POST /auth/login` (form fields `username` = email, `password`) returns `access_token` and `refresh_token`; send `Authorization: Bearer <access_token>`. `POST /auth/refresh` exchanges a refresh token. Roles: `viewer` (read), `analyst` (read + act), `admin` (everything, user management, settings).

**SIEM ingestion** — `POST /logs/ingest` accepts either `X-API-Key: <INGEST_API_KEY>` (machine sources) or an analyst/admin bearer token. Body: `{"events":[{"source","category","severity","message","source_ip","hostname",...}]}` (max 1000). Events are resolved to assets by `hostname`/IP and correlated into risks.

**Blocklist feed** — `GET /blocklist` and `GET /blocklist.txt?kind=ip|domain|hash` (same auth options) for firewalls/proxies/EDR.

This table is generated from the running service's OpenAPI schema.

## AI Agents

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/agents/discussions` | risk_id, incident_id, limit |
| POST | `/api/v1/agents/discussions` | — |
| POST | `/api/v1/agents/discussions/stream` | — |
| GET | `/api/v1/agents/discussions/{discussion_id}` | — |
| POST | `/api/v1/agents/query` | — |
| GET | `/api/v1/agents/status` | — |

## Alerts

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/alerts` | page, page_size, min_severity, status, category, asset_id, q, since |
| POST | `/api/v1/alerts/mark-seen` | — |
| GET | `/api/v1/alerts/stats` | hours |
| GET | `/api/v1/alerts/unread` | — |
| POST | `/api/v1/alerts/{log_id}/acknowledge` | — |
| POST | `/api/v1/alerts/{log_id}/dismiss` | — |

## Assets

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/assets` | page, page_size, asset_type, criticality, exposure, business_unit, q |
| POST | `/api/v1/assets` | — |
| GET | `/api/v1/assets/connections` | — |
| POST | `/api/v1/assets/connections` | — |
| DELETE | `/api/v1/assets/connections/{connection_id}` | — |
| POST | `/api/v1/assets/import` | — |
| GET | `/api/v1/assets/stats` | — |
| DELETE | `/api/v1/assets/{asset_id}` | — |
| GET | `/api/v1/assets/{asset_id}` | — |
| PATCH | `/api/v1/assets/{asset_id}` | — |
| GET | `/api/v1/assets/{asset_id}/events` | limit |
| POST | `/api/v1/assets/{asset_id}/isolate` | — |
| POST | `/api/v1/assets/{asset_id}/restore` | — |
| GET | `/api/v1/assets/{asset_id}/risks` | — |

## Audit Ledger

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/ledger` | — |
| GET | `/api/v1/ledger/blocks` | skip, limit, event_type, actor, resource_id, q |
| GET | `/api/v1/ledger/blocks/{block_number}` | — |
| GET | `/api/v1/ledger/export` | — |
| GET | `/api/v1/ledger/public-key` | — |
| GET | `/api/v1/ledger/verify` | — |

## Authentication

| Method | Path | Query parameters |
| --- | --- | --- |
| POST | `/api/v1/auth/change-password` | — |
| POST | `/api/v1/auth/login` | — |
| POST | `/api/v1/auth/logout` | — |
| GET | `/api/v1/auth/me` | — |
| PUT | `/api/v1/auth/me` | — |
| POST | `/api/v1/auth/refresh` | — |
| POST | `/api/v1/auth/register` | — |

## Blocklist

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/blocklist` | — |
| GET | `/api/v1/blocklist.txt` | kind |
| DELETE | `/api/v1/blocklist/{indicator_id}` | — |

## CVE Intelligence

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/cves` | page, page_size, severity, min_cvss, has_exploit, kev, q, sort |
| GET | `/api/v1/cves/stats` | — |
| GET | `/api/v1/cves/trending` | limit |
| GET | `/api/v1/cves/{cve_id}` | — |

## Dashboard

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/dashboard/actions` | limit |
| GET | `/api/v1/dashboard/departments` | — |
| GET | `/api/v1/dashboard/executive` | — |
| GET | `/api/v1/dashboard/overview` | — |
| GET | `/api/v1/dashboard/trend` | days |
| GET | `/api/v1/dashboard/vulnerabilities` | — |

## Digital Twin

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/twin/attack-paths` | start_id, target_id, algorithm, max_depth |
| GET | `/api/v1/twin/attack-types` | — |
| GET | `/api/v1/twin/blast-radius/{asset_id}` | max_hops |
| GET | `/api/v1/twin/critical-paths` | — |
| POST | `/api/v1/twin/simulate` | — |
| GET | `/api/v1/twin/topology` | — |

## Health

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/health` | — |
| GET | `/health/ready` | — |

## Incidents

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/incidents` | page, page_size, status, severity, active_only, q |
| POST | `/api/v1/incidents` | — |
| POST | `/api/v1/incidents/from-risk` | — |
| GET | `/api/v1/incidents/stats` | — |
| GET | `/api/v1/incidents/{incident_id}` | — |
| PATCH | `/api/v1/incidents/{incident_id}` | — |
| POST | `/api/v1/incidents/{incident_id}/close` | — |
| POST | `/api/v1/incidents/{incident_id}/notes` | — |

## Playbooks

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/playbooks` | active_only, category |
| POST | `/api/v1/playbooks` | — |
| GET | `/api/v1/playbooks/executions` | page, page_size, status, risk_id, incident_id, playbook_id |
| POST | `/api/v1/playbooks/executions` | — |
| GET | `/api/v1/playbooks/executions/{execution_id}` | — |
| POST | `/api/v1/playbooks/executions/{execution_id}/cancel` | — |
| POST | `/api/v1/playbooks/executions/{execution_id}/steps/{order}/complete` | — |
| POST | `/api/v1/playbooks/executions/{execution_id}/steps/{order}/skip` | — |
| GET | `/api/v1/playbooks/{ident}` | — |
| PATCH | `/api/v1/playbooks/{ident}` | — |

## Reports

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/reports` | — |
| GET | `/api/v1/reports/analytics` | months, weeks |
| POST | `/api/v1/reports/board` | — |
| GET | `/api/v1/reports/{report_id}` | — |

## Risk Management

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/risks` | page, page_size, status, level, category, asset_id, min_bwvs, q, open_only |
| POST | `/api/v1/risks` | — |
| GET | `/api/v1/risks/stats` | — |
| GET | `/api/v1/risks/top10` | limit |
| GET | `/api/v1/risks/{risk_id}` | — |
| GET | `/api/v1/risks/{risk_id}/history` | — |
| POST | `/api/v1/risks/{risk_id}/investigate` | — |
| GET | `/api/v1/risks/{risk_id}/playbooks` | — |
| POST | `/api/v1/risks/{risk_id}/recalculate` | — |
| PUT | `/api/v1/risks/{risk_id}/status` | — |

## Root

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/` | — |

## SIEM Ingestion

| Method | Path | Query parameters |
| --- | --- | --- |
| POST | `/api/v1/logs/ingest` | — |

## Search

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/search` | q |

## Settings & System

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/settings/integrations` | — |
| PUT | `/api/v1/settings/integrations` | — |
| POST | `/api/v1/settings/jobs/{job_id}/run` | — |
| GET | `/api/v1/settings/organization` | — |
| PUT | `/api/v1/settings/organization` | — |
| GET | `/api/v1/settings/system` | — |

## Users

| Method | Path | Query parameters |
| --- | --- | --- |
| GET | `/api/v1/users` | — |
| POST | `/api/v1/users` | — |
| PATCH | `/api/v1/users/{user_id}` | — |
