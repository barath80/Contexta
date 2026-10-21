# Contexta

**Autonomous, context-aware threat intelligence and business-risk platform.**
Contexta turns raw vulnerability feeds and security events into a short, ranked list of *the risks that matter to
your business* — with evidence-grounded AI analysis, executable response playbooks, digital-twin attack simulation
and a tamper-evident audit trail.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-async-009688) ![Next.js](https://img.shields.io/badge/Next.js-16-black) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791) ![Gemini](https://img.shields.io/badge/Gemini-optional-orange)

> **No mock data.** Nothing is pre-loaded or simulated: you add your assets, Contexta pulls live intelligence
> (CISA KEV, NVD, EPSS), and risks appear when the two are correlated.
> Source code lives in [`Horizon_Beach_Hacks-main/project_cyber`](Horizon_Beach_Hacks-main/project_cyber).

## Contents

**Part I — The solution**
[Problem statement](#i1-problem-statement) ·
[Solution](#i2-the-solution) ·
[How it solves the problem](#i3-how-it-solves-the-problem--end-to-end) ·
[Uniqueness](#i4-uniqueness-how-contexta-differs-from-existing-tools) ·
[Innovation & novelty](#i5-innovation-and-novelty) ·
[Tech stack: why this, not that](#i6-technology-stack--why-this-and-not-that) ·
[AI agents](#i7-the-ai-agents--what-they-are-why-and-how-they-work) ·
[Workflows](#i8-workflows-in-depth) ·
[Worked example](#i9-worked-example) ·
[Trust & limits](#i10-trust-safety-and-limits) ·
[Impact & roadmap](#i11-impact-and-roadmap)

**Part II — Technical reference**
[Idea at a glance](#ii1-the-problem-and-the-idea) ·
[Features](#ii2-features) ·
[Architecture](#ii3-architecture) ·
[Workflows](#ii4-how-it-works-workflows) ·
[Core engines](#ii5-core-engines) ·
[Data model](#ii6-data-model) ·
[Security model](#ii7-security-model) ·
[Tech stack](#ii8-tech-stack) ·
[Getting started](#ii9-getting-started) ·
[Configuration](#ii10-configuration) ·
[API](#ii11-api) ·
[Project structure](#ii12-project-structure) ·
[Testing](#ii13-testing) ·
[Known limitations](#ii14-known-limitations)

---

# Part I — The solution

## I.1 Problem statement

### 1.1 The situation
* Tens of thousands of CVEs are published every year. A mid-size company runs hundreds of assets with thousands of software components.
* Scanners and feeds report hundreds or thousands of "critical" or "high" findings. Teams cannot patch them all, so **ordering decides whether the company is breached**.

### 1.2 Why existing practice fails

| Gap | Consequence |
| --- | --- |
| **CVSS is context-free.** A 9.8 on a dev box and a 9.8 on the payroll server look identical. | Effort is spent on the wrong assets. |
| **Exploitation is ignored.** Only a small fraction of CVEs are ever exploited; CISA's KEV list and EPSS say which. | Teams patch theoretical risks while exploited ones stay open. |
| **No version awareness in feeds.** KEV lists "vendor + product", not versions. | Patched systems are flagged → alert fatigue → real alerts ignored. |
| **Risk is not in money.** Executives cannot weigh "CVSS 8.1" against budget. | Security is under-funded or mis-prioritised. |
| **Analysis is manual and inconsistent.** Each analyst reasons differently, undocumented. | Slow response, no shared reasoning, no repeatability. |
| **Response is tribal knowledge.** Runbooks live in wikis. | Steps skipped under pressure; no record of what was done. |
| **Audit trails are mutable.** Logs in a database can be edited. | Weak forensics and compliance evidence. |
| **Tools are siloed.** Scanner, SIEM, ticketing, SOAR and reporting are separate products. | Context is lost between them. |

### 1.3 The problem in one sentence
> *Given my real assets, the live threat landscape and my business, **what should I fix or contain first, why, what will it cost if I don't, what exactly should I do — and can I prove afterwards what was decided and done?***

## I.2 The solution

Contexta is a single platform that **correlates your asset inventory with live threat intelligence and security events, scores each risk by business impact and real-world exploitation, explains it with a team of specialised AI agents, drives response through executable playbooks, and seals every decision in a tamper-evident ledger.**

```mermaid
flowchart TB
    subgraph Inputs
        A[Asset inventory<br/>software + versions, exposure, criticality, ₹ impact]
        B[Threat intel feeds<br/>CISA KEV · NVD · EPSS]
        C[Security events<br/>from your SIEM]
    end
    subgraph Understand
        D[Version-aware correlation]
        E[BWVS score]
        F[Freshness × Trend ranking]
    end
    subgraph Decide
        G[5-agent analysis + consensus]
        H[Digital-twin simulation<br/>attack paths & blast radius]
        I[Expected ₹ loss]
    end
    subgraph Act
        J[Incident]
        K[Playbook execution<br/>automated + manual steps]
        L[Webhooks / containment]
    end
    M[(Signed audit ledger)]
    A & B & C --> D --> E --> F --> G & H & I
    G & H & I --> J --> K --> L
    D & E & G & J & K & L -.every action.-> M
```

### The five ideas that make it work
1. **Context over severity** — BWVS puts the business (criticality, exposure, revenue) next to technical severity.
2. **Evidence over opinion** — exploitation signals (KEV, EPSS, live events) and freshness drive ranking; scores decay when nothing new happens.
3. **Facts → AI, never AI → facts** — agents receive a frozen evidence pack and must cite it; output is validated JSON.
4. **Closed loop** — risk → analysis → incident → playbook → resolution, with state flowing back (e.g. playbook completion resolves the risk).
5. **Provable history** — every step is hash-chained and signed, so the record can be independently verified.

## I.3 How it solves the problem — end to end

| Problem | How Contexta solves it | Where |
| --- | --- | --- |
| Context-free severity | **BWVS** = CVSS + exploit activity + exposure + criticality + revenue impact + AI relevance | `risk_engine/bwvs.py` |
| Exploitation ignored | CISA KEV, EPSS, public-exploit signals raise a **trend factor up to 2×** | `risk_engine/ranking.py` |
| Stale noise | **Freshness half-life of 7 days** since last new evidence | `risk_engine/ranking.py` |
| Patched systems flagged | **Version-range matching** from NVD CPE data; patched assets skipped, stale risks auto-closed | `services/software_matcher.py` |
| Risk not in money | **Probability-weighted ₹ exposure** per asset/business unit with visible assumptions | `services/risk_service.py`, executive view |
| Inconsistent analysis | **5 specialised agents** with fixed roles, shared evidence, consensus | `agents/` |
| "What if we're hit?" | **Digital twin**: attack paths, blast radius, scenario loss | `twin/engine.py` |
| Tribal-knowledge response | **Executable playbooks** with automated and manual steps and tracking | `services/playbook_service.py` |
| Mutable logs | **Ed25519-signed hash chain** + scheduled verification | `services/ledger_service.py` |
| Siloed tools | One workflow from intelligence to closure, one UI | whole system |

## I.4 Uniqueness: how Contexta differs from existing tools

| Capability | Vulnerability scanners (Nessus, Qualys, Rapid7) | Threat-intel platforms (MISP, OpenCTI) | SIEM (Splunk, Elastic, Sentinel) | SOAR (XSOAR, Shuffle) | GRC / risk-quant (RiskLens, Archer) | **Contexta** |
| --- | --- | --- | --- | --- | --- | --- |
| Finds vulnerabilities by scanning | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ (uses your inventory + feeds; no scanner needed) |
| Live exploitation intelligence (KEV/EPSS) in ranking | partial / add-on | ✅ (data only) | ❌ | ❌ | ❌ | ✅ drives the ranking |
| **Business-context scoring** | limited tags | ❌ | ❌ | ❌ | ✅ (manual inputs) | ✅ automated per asset |
| Version-aware auto-suppression of patched systems | ✅ (agent-based) | ❌ | ❌ | ❌ | ❌ | ✅ from NVD ranges, no agent |
| Money-denominated exposure | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ computed from live risks |
| Multi-agent AI reasoning on evidence | ❌ | ❌ | emerging copilots | ❌ | ❌ | ✅ 5 roles + consensus |
| Attack-path / blast-radius simulation | add-on | ❌ | ❌ | ❌ | ❌ | ✅ built in |
| Executable response playbooks | ❌ | ❌ | limited | ✅ | ❌ | ✅ tied to the risk |
| Cryptographic audit ledger | ❌ | ❌ | ❌ | partial | ❌ | ✅ |
| Runs without agents/connectors, works with partial data | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Cost / weight | heavy licence | medium | very heavy | heavy | heavy | lightweight, self-hosted |

**Positioning.** Contexta does not replace a scanner, SIEM or SOAR; it sits **above** them as the decision layer — consuming their outputs (inventory, events) and answering *"what first, why, what will it cost, and what do we do?"* in one place. Teams that cannot afford the full stack get an end-to-end loop; teams that have it get prioritisation and proof.

## I.5 Innovation and novelty

> Individual building blocks (CVSS, EPSS, hash chains, LLMs) are established. The novelty is in **how they are combined and constrained**. We make no claim that any single piece is new in isolation.

### 5.1 BWVS — a transparent, tunable business-weighted score
Scores that include business context usually live in proprietary black boxes. BWVS is an open, six-factor weighted formula whose breakdown is shown for every risk (bars in the risk panel) and stored per calculation (`risk_scores`) so the *change* in score is auditable.

### 5.2 Priority that decays and accelerates
`Priority = BWVS × 0.5^(age/7d) × Trend(1–2)`. A risk with no new evidence fades; one that becomes KEV-listed, gets a high EPSS, or sees rising attack events jumps. Most tools produce a static number.

### 5.3 Version-aware correlation from public data only
KEV omits versions, so most free tooling over-alerts. Contexta enriches relevant CVEs from NVD CPE ranges, tags each match *confirmed / not verified*, drops patched ones, and **auto-closes risks when software is upgraded** — without an agent on the host.

### 5.4 Constrained multi-agent reasoning ("evidence-grounded debate")
Instead of one free-form chatbot, five role-specific agents see the same frozen **evidence pack**, run in a staged pipeline (so later agents can challenge earlier ones), return **validated JSON**, and a **deterministic consensus** (severity vote, agreement score, dissent, prioritised actions) is computed in code — not by the LLM. The evidence is SHA-256 hashed and recorded in the ledger so any conclusion can be traced to the facts it used. The system works without an LLM (rules mode), which makes outputs testable and offline-capable.

### 5.5 Risk expressed as expected loss with exposed assumptions
`P = 1 − Π(1 − pᵢ)` per asset, `Loss = daily revenue × downtime × P`. Every response includes the assumptions, so executives see *how* the number was derived.

### 5.6 Digital twin built from the same inventory
No separate modelling project: the asset list and connections become a graph instantly. Scenario simulation (ransomware, APT, insider, DDoS) produces paths, blast radius, ATT&CK-mapped timeline, and ₹ loss using the same revenue figures as the risk model.

### 5.7 Tamper-evident ledger that also covers *who did what*
Beyond a plain hash chain, verification cross-checks the human-readable columns (actor, event type, resource) against the **signed payload**, closing the gap where a database editor could rewrite attribution without breaking hashes.

### 5.8 Graceful degradation as a design rule
No LLM key → rules engine; no Redis → in-memory limiter; a failed feed → partial sync with reported errors; an LLM failure mid-analysis → that agent falls back and is flagged. The platform stays useful in each case.

## I.6 Technology stack — why this and not that

### 6.1 Summary

```mermaid
flowchart LR
    subgraph Client
        N[Next.js 16 · React 19<br/>TypeScript · Tailwind · Recharts]
    end
    subgraph Server
        F[FastAPI · Pydantic v2 · SQLAlchemy 2 async]
        AP[APScheduler]
        NX[NetworkX]
        CR[cryptography: Ed25519]
    end
    subgraph Data
        P[(PostgreSQL / SQLite)]
        R[(Redis)]
    end
    G[Gemini]
    N --> F --> P
    F --> R
    F --> AP & NX & CR
    F --> G
```

### 6.2 Backend framework

| Option | Verdict |
| --- | --- |
| **FastAPI (chosen)** | Native `async` (feed calls, SSE streaming, many concurrent reads), automatic validation + OpenAPI from type hints, dependency injection for auth/RBAC, Python ecosystem for security/data/AI libraries. |
| Django + DRF | Excellent admin/ORM but sync-first; async support is partial; heavier for an API-only service; ORM async story weaker. |
| Flask | Minimal, but validation, async, OpenAPI and DI must be assembled by hand. |
| Node (Express/NestJS) | Great concurrency, but security-data and graph/crypto/AI libraries are richer in Python; two languages would be needed for the analytics. |
| Spring Boot (Java) | Very robust but heavier to develop and deploy for this scope; slower iteration. |
| Go | Fast and small, but far fewer ready libraries for NVD/CPE parsing, graphs and LLM tooling. |

### 6.3 Database

| Option | Verdict |
| --- | --- |
| **PostgreSQL (chosen, SQLite for dev)** | Relational integrity across risks ↔ assets ↔ CVEs ↔ incidents; JSON columns for flexible payloads; transactions (ledger/audit ordering); mature backups; MVCC means feed syncs never block users. SQLite gives a zero-setup dev mode through the same SQLAlchemy code. |
| MongoDB | Flexible documents, but the domain is strongly relational (joins for correlation, ranking, dashboards) and needs transactions; we'd re-implement integrity in code. |
| Elasticsearch / OpenSearch | Great for log search, poor as system of record; heavier to operate. Could be added later as a log index. |
| Neo4j | Natural for graphs, but our graph is derived from a few thousand assets — NetworkX in memory is simpler and has no extra server. |
| Time-series DB (Influx/Timescale) | Overkill; we store low-frequency snapshots (`risk_snapshots`). |

**ORM:** SQLAlchemy 2 (async) over raw SQL or Tortoise/Prisma: mature, dialect-portable (SQLite ↔ PostgreSQL), Alembic migrations.

### 6.4 Scheduler

| Option | Verdict |
| --- | --- |
| **APScheduler (chosen)** | In-process cron/interval, no broker, job history recorded in `job_runs`; ideal for a small number of periodic jobs. |
| Celery + broker | Needed for large distributed workloads; adds Redis/RabbitMQ and workers for three periodic jobs. |
| OS cron / Kubernetes CronJob | Loses app context, harder to show status in the UI. |
| Airflow/Prefect | Powerful orchestration, far more infrastructure than needed. |

*Trade-off:* in-process means one API replica. Moving jobs to a worker is a straightforward future step.

### 6.5 Graph engine

| Option | Verdict |
| --- | --- |
| **NetworkX (chosen)** | Pure Python, simple BFS/DFS/shortest-path APIs, ample for thousands of nodes, no server. |
| Neo4j / graph DB | Scales to millions of relationships; operational cost not justified here. |
| igraph / graph-tool | Faster, but C dependencies complicate installs; performance isn't the bottleneck. |

### 6.6 AI model and approach

| Option | Verdict |
| --- | --- |
| **Google Gemini behind an `AIClient` interface (chosen)** | Reliable structured-JSON output, long context for evidence packs, generous free tier for adoption, low latency "flash" tier. The interface isolates the provider so it can be swapped. |
| OpenAI GPT / Anthropic Claude | Equally capable; selectable by implementing the same interface. Chosen provider was driven by free-tier availability and project requirements, not capability limits. |
| Local open models (Llama, Mistral via Ollama) | Best for data residency; lower reasoning quality on long evidence and higher hardware cost. A good future option for air-gapped sites. |
| Fine-tuned custom model | Needs labelled incident data we do not have; retrieval of *facts* is a better fit than training. |
| **Rules engine fallback (included)** | Guarantees deterministic behaviour with no API key and makes agent logic unit-testable. |

**Why agents + retrieval of facts rather than one big prompt?** Specialisation keeps each prompt short and focused; staged order lets later agents challenge earlier ones; structured outputs make results machine-checkable; consensus in code avoids LLM drift.

### 6.7 Frontend

| Option | Verdict |
| --- | --- |
| **Next.js + React + TypeScript (chosen)** | Production build pipeline, standalone Docker output, built-in security-header configuration, typed API client catches contract drift at compile time. |
| Create React App / plain Vite SPA | Fine, but CRA is unmaintained; Next adds routing/headers/standalone server out of the box. |
| Angular | Strong structure, heavier and slower to iterate for a small team. |
| Vue/Nuxt | Comparable; React's ecosystem (Recharts, Lucide) and team familiarity decided it. |
| Server-rendered templates (Jinja/HTMX) | Simple, but streaming agent chats, polling dashboards and rich modals suit a client app. |

**Styling/charts:** Tailwind (fast, consistent, dark mode) over CSS-in-JS/Bootstrap; Recharts (declarative React charts) over D3 (more code) or Chart.js (imperative).

### 6.8 Authentication & cryptography

| Option | Verdict |
| --- | --- |
| **JWT access + refresh with server-side `token_version` (chosen)** | Stateless API calls, plus instant revocation (logout, role change, disable, password change) by bumping the version. |
| Server sessions (cookies) | Simple revocation, but needs shared session store and CSRF handling; JWT bearer suits a separate SPA/API. |
| OAuth/OIDC/SSO | Right for enterprises; planned integration (identity provider), not a substitute for a self-contained start. |
| **Ed25519 signatures (chosen)** | Small, fast, deterministic, no parameter or padding pitfalls. RSA is larger/slower; ECDSA needs careful nonce handling. |
| Public blockchain / Hyperledger | Adds consensus, cost and complexity for a single-organisation audit log. A hash-chained, signed, verifiable ledger gives the integrity property needed; periodic export can anchor it externally. |

### 6.9 Data sources

| Source | Provides | Why |
| --- | --- | --- |
| **CISA KEV** | Confirmed exploited-in-the-wild CVEs | Highest-signal exploitation evidence, free, authoritative |
| **NVD API 2.0** | CVSS, CWE, CPE configurations incl. **version ranges** | Canonical severity and the only free source of structured version bounds |
| **FIRST EPSS** | 30-day exploitation probability | Forward-looking; complements KEV (past) |
| Commercial feeds (Recorded Future, Mandiant) | Richer intel | Paid; can be added behind the same collector interface |

## I.7 The AI agents — what they are, why, and how they work

### 7.1 Why five agents?
A real SOC consults different specialists. Each agent owns one question set, which prevents a single prompt from trying to be everything and makes disagreement visible.

| Agent | Role | Answers | Typical structured output |
| --- | --- | --- | --- |
| **Security Analyst** | Triage and technical severity | What is the flaw, how exploitable is it *here*, is it reachable? | severity, attack vector, affected components |
| **Threat Intelligence Analyst** | External context | Is it exploited in the wild (KEV/ransomware/EPSS)? Related threats? | exploitation status, actor/campaign notes, **risk-feedback** (AI relevance for BWVS) |
| **Digital Forensics Analyst** | Internal evidence | Which events, IPs, users, timeline, IOCs hit this asset? Is there compromise? | IOCs, timeline, compromise likelihood |
| **Business Impact Analyst** | Money & operations | Revenue at risk, downtime, who depends on the asset, compliance impact | exposure ₹, dependants, regulatory notes |
| **Response Coordinator** | Action plan | What to do now, which playbook, who to notify, escalate? | immediate actions, `playbook_slug`, escalation flag |

### 7.2 The evidence pack (what agents see)
Built from the database for the chosen risk/incident: organisation profile, risk and score components, CVE details (CVSS, KEV, EPSS, CWEs), asset (exposure, criticality, ₹ impact, software), **network neighbourhood** from the twin, recent security events and IOCs, same-CVE exposure on other assets, related risks on the asset, previous assessments, and **available playbooks**. It is size-trimmed deterministically and hashed (SHA-256).

### 7.3 Pipeline

```mermaid
flowchart TB
    EV[Evidence pack<br/>+ SHA-256 hash] --> S1
    subgraph S1[Stage 1 · parallel]
        AN[Analyst]
        IN[Intel]
    end
    S1 --> FO[Stage 2 · Forensics<br/>sees Stage 1]
    FO --> BU[Stage 3 · Business<br/>sees Stages 1-2]
    BU --> RE[Stage 4 · Response<br/>sees all]
    RE --> CO[Consensus — computed in code]
    CO --> OUT[Consensus severity · agreement · dissent<br/>prioritised actions · recommended playbook · escalation]
    IN -. AI-relevance feedback .-> BW[BWVS re-score]
    OUT --> LED[(Ledger: evidence hash + result)]
```

* **Prompting rules (all agents):** use only the evidence; never invent hosts, IPs, CVEs, dates; say what is missing; speak to colleagues by name; ≤110 words; severity ∈ {low, medium, high, critical}; reply with a single JSON object.
* **Validation:** responses are normalised (clamped confidence, whitelisted severities, trimmed lists); an empty/invalid reply raises a typed error instead of leaking garbage.
* **Consensus (deterministic):** confidence-weighted severity vote; agreement score and level; dissenting agents with reasons; merged key findings; de-duplicated prioritised recommendations; playbook (only if it exists in the evidence); escalation if consensus is high/critical or the Response agent flags it.
* **Executive summary:** written by the LLM *from the consensus object* (or a template in rules mode).
* **Feedback loop:** when AI is on, Intel's relevance assessment can adjust the AI-relevance factor of BWVS (bounded) and is recorded.
* **Streaming:** the API emits Server-Sent Events (`started`, `typing`, `message`, `consensus`, `risk_feedback`, `done`/`error`) so the UI shows the agents "speaking" in real time.
* **Resilience:** if the LLM fails after the first stage the affected agent falls back to rules (`degraded` flag); if it fails at the start the run reports `ai_unavailable` rather than inventing output.

### 7.4 Why this beats a single chatbot
| Single chatbot | Evidence-grounded agents |
| --- | --- |
| Hallucination risk, free text | Fixed evidence, validated JSON, "unknown" is allowed |
| No disagreement visible | Dissent is surfaced explicitly |
| Not reproducible | Evidence hash + deterministic consensus |
| Needs the LLM to function | Rules mode produces the same structure offline |

## I.8 Workflows in depth

### 8.1 Intelligence → ranked risk
```mermaid
flowchart TB
    T[Timer 6h / button] --> K[Fetch CISA KEV<br/>upsert, commit]
    K --> E[NVD lookup for CVEs matching your assets<br/>CVSS, CPE version ranges · retry with backoff]
    E --> RC[Recent high/critical NVD CVEs]
    RC --> MT[Match product tokens to installed software]
    MT --> VC{Version check}
    VC -- outside range --> SK[Skip / auto-close existing risk]
    VC -- inside range --> CF[Create risk: version confirmed]
    VC -- no data --> UV[Create risk: version not verified]
    CF & UV --> EP[EPSS for open risks]
    EP --> SC[BWVS → freshness → trend → priority]
    SC --> TP[Top-10 + snapshot for trends]
```

### 8.2 Detection → response
```mermaid
sequenceDiagram
    participant SIEM
    participant API
    participant Risk
    participant Analyst
    participant Agents
    participant Playbook
    participant Ledger
    SIEM->>API: events (API key)
    API->>Risk: correlate to asset, escalate risk
    Analyst->>API: open risk → AI analysis
    API->>Agents: evidence → 5 agents → consensus
    Agents-->>Analyst: recommended playbook, escalation
    Analyst->>Playbook: run
    Playbook->>Playbook: automated steps (isolate, block IOCs, collect evidence, notify)
    Playbook-->>Analyst: awaiting manual step
    Analyst->>Playbook: mark done
    Playbook->>Risk: resolve risk, close timeline
    API->>Ledger: every step (signed)
```

### 8.3 Playbook step types
`isolate_asset`, `restore_asset`, `collect_evidence`, `block_iocs` (public IPs only; feeds `/blocklist.txt`), `scan_related_hosts` (uses the twin to find neighbours), `notify` (webhook or in-app), `run_agent_analysis`. Steps can be `automated` or `manual`, required or optional, with `on_failure = stop | continue`.

### 8.4 Request lifecycle & audit
```mermaid
flowchart LR
    RQ[Request] --> RL[Rate limit] --> JW[JWT → user → role check] --> H[Handler]
    H --> TX[(DB transaction)]
    TX -- commit ok --> AQ[Queued audit entries written to ledger]
    TX -- rollback --> NA[No ledger entry]
```
Audit entries are written only after the business transaction commits, so rolled-back work is never "recorded" and the ledger never contends with the request's own write lock.

### 8.5 Executive path
`risk_snapshots` (captured at each re-score) feed trends; `expected_loss` aggregates by asset, business unit and category; control-health metrics (KEV open, internet-facing with serious risk, SLA breaches, MTTR) are computed from live data. The board report is written by Gemini from these metrics (or deterministically) and stored.

## I.9 Worked example

*(Illustrative: product names, versions and figures are invented to show the flow.)*

> **Assets:** `VPN Gateway` (internet-facing, core backend, ₹20 L/day, runs *Fortinet FortiOS 7.0.1*) and `Dev Wiki` (internal, dev/test, runs *Confluence 8.5.0*).

1. KEV sync brings in a FortiOS CVE; NVD lookup adds CVSS 9.8 and range `< 7.0.14`. Installed 7.0.1 is inside the range → **confirmed**. A Confluence CVE with range `< 8.5.0` does **not** match 8.5.0 → no risk.
2. BWVS for the VPN risk is high (CVSS 9.8, KEV = exploit 10, internet-facing 10, core backend 8, ₹20 L = 10) → **~90, critical**; KEV + EPSS push the trend factor towards 2 → top of the list.
3. Analyst opens the risk and runs **AI analysis**: Intel confirms KEV/ransomware use; Forensics sees failed-login bursts from one IP on the gateway; Business estimates ₹ exposure; Response recommends the *Malware/Breach containment* playbook and escalation. Consensus: **critical, high agreement**.
4. Analyst runs the playbook: the asset is isolated, IOCs are blocked (public IPs only), evidence is collected and the team is notified by webhook; a manual "apply vendor patch" step waits for the analyst.
5. Patch applied, asset software updated to 7.0.14 → next sync **auto-closes** any remaining stale risk; the executive view shows lower exposure; the ledger holds a signed record of every step and the evidence hash behind the AI conclusion.

## I.10 Trust, safety and limits

* **Security controls:** see Part II, section II.7 — RBAC, token revocation, throttling, SSRF protection, CSP/HSTS, dependency audit, signed ledger.
* **AI safety:** agents are read-only; they cannot change data. Output is validated and shown as advice; untrusted log text is included in evidence, so prompts instruct the model to treat evidence as data.
* **Data protection:** no secrets in the repo; production refuses weak configuration; LLM calls send only the evidence pack (organisation and risk context) — disable by leaving `GEMINI_API_KEY` empty.
* **Known limits:** KEV lacks versions (NVD enrichment is rate-limited without a key); loss estimates depend on the revenue figures you enter; ledger key co-located with DB unless externalised; single API replica; no built-in scanner or SSO yet.

## I.11 Impact and roadmap

| Outcome | How it is achieved |
| --- | --- |
| Fewer, better findings | Version-aware matching + context scoring + freshness decay |
| Faster response | Pre-built evidence, agent consensus, playbooks |
| Better decisions & funding | ₹ exposure with assumptions; board report |
| Compliance & forensics | Verifiable signed ledger |
| Low adoption cost | Works with just an asset list; optional AI/SIEM |

**Roadmap:** SSO/OIDC; connectors (CMDB, EDR, cloud inventories); native webhooks for Slack/Teams/ServiceNow; background worker for horizontal scale; external ledger anchoring (e.g. periodic hash publication); pluggable LLM providers (including local models); SBOM ingestion for exact software inventories; user-tunable BWVS weights per organisation.

---

# Part II — Technical reference

## II.1 The problem and the idea

Organisations face thousands of new CVEs a year. CVSS says how bad a flaw is *in general*; it says nothing about
**your** payroll server, whether the flaw is already being **exploited**, or what an outage would **cost**.
Security teams drown in "critical" findings, patch in the wrong order, and cannot explain risk to executives in money.

Contexta ranks risk by **business impact + real-world exploitation + freshness**, explains each risk with a small
team of specialised AI agents, lets analysts execute response playbooks, and records every action in a
cryptographically signed ledger.

```mermaid
flowchart LR
    A[Live threat feeds<br/>CISA KEV · NVD · EPSS] --> C{Correlate with<br/>YOUR asset inventory}
    B[SIEM events<br/>POST /logs/ingest] --> C
    C --> D[BWVS score<br/>technical + business context]
    D --> E[Priority = BWVS × Freshness × Trend]
    E --> F[Top-10 ranked risks]
    F --> G[5 AI agents → consensus]
    F --> H[Playbook execution]
    F --> I[Executive view<br/>₹ exposure]
    G & H & I --> L[(Signed audit ledger)]
```

## II.2 Features

| Area | What you get |
| --- | --- |
| **Live threat intelligence** | CISA KEV catalogue, NVD CVSS/CPE data, FIRST EPSS exploit probability; scheduled + on-demand sync |
| **Version-aware matching** | CVEs are matched to installed software *and checked against NVD affected-version ranges*; patched software is not flagged and stale risks auto-close |
| **BWVS scoring** | Business-Weighted Vulnerability Score (0-100) combining CVSS, exploit activity, exposure, asset criticality, revenue impact and AI relevance |
| **Dynamic ranking** | Priority decays with a 7-day half-life and is boosted by KEV / ransomware / EPSS / rising event volume |
| **Multi-agent analysis** | Analyst, Threat-Intel, Forensics, Business-Impact and Response agents debate in a staged pipeline and reach a consensus; streamed live to the UI |
| **Digital twin** | Network graph from your assets; BFS/DFS attack paths, blast radius, critical paths, ransomware/APT/insider/DDoS simulations with ₹ loss estimates |
| **Playbooks** | 5 response playbooks with automated (isolate, block IOCs, collect evidence, notify, scan) and manual steps; full execution tracking |
| **Incidents** | Opened from a risk, timeline, notes, assignment, closure that can resolve the linked risk |
| **SIEM ingestion** | Authenticated event API; events resolve to assets and create/escalate risks |
| **Executive & reports** | Probability-weighted financial exposure, SLA breaches, trends, board report (LLM or rules-written), CSV export |
| **Audit ledger** | SHA-256 hash chain + Ed25519 signatures; one-click verification; tamper detection incl. actor/event columns |
| **Operations** | Role-based access, rate limiting, background jobs with run history, health probes, Alembic migrations, Docker Compose |

## II.3 Architecture

```mermaid
flowchart TB
    subgraph Browser
        UI[Next.js 16 / React 19 UI<br/>Overview · Risks · Alerts · Incidents · Playbooks<br/>Simulator · Assets · Reports · Executive · Ledger · Settings]
    end

    subgraph API["FastAPI service (async)"]
        direction TB
        MW[Middleware: CORS · rate limit · security headers · request-id]
        AUTH[JWT auth + RBAC<br/>viewer / analyst / admin]
        R[Routers /api/v1]
        subgraph Services
            RS[Risk service]
            AS[Asset service]
            CS[CVE service]
            IS[Incident service]
            PS[Playbook engine]
            LS[Log / alert service]
            DS[Dashboard & report service]
            TS[Twin service]
            LG[Ledger service]
        end
        subgraph Engines
            BW[BWVS + ranking]
            SM[Software / version matcher]
            TW[Digital-twin engine<br/>NetworkX]
            AG[Agent orchestrator<br/>5 agents + consensus]
            SIG[Ed25519 signer]
        end
        SCH[APScheduler jobs<br/>feed sync · risk refresh · ledger verify]
    end

    subgraph Data
        PG[(PostgreSQL<br/>SQLite in dev)]
        RD[(Redis<br/>rate limits)]
    end

    subgraph External
        KEV[CISA KEV]
        NVD[NVD API 2.0]
        EPSS[FIRST EPSS]
        GEM[Google Gemini<br/>optional]
        SIEM[Your SIEM / log shipper]
        WH[Webhooks<br/>Slack · firewall automation]
    end

    UI -- HTTPS JSON + SSE --> MW --> AUTH --> R --> Services
    Services --> Engines
    Services --> PG
    MW --> RD
    SCH --> Services
    SCH --> KEV & NVD & EPSS
    AG --> GEM
    SIEM -- X-API-Key --> R
    PS --> WH
    LG --> SIG
```

**Design principles**

* **Evidence first.** Every analysis (agent, report, score) is computed from stored facts; the AI never invents data.
* **Degrade gracefully.** No Gemini key → deterministic rules engine over the same evidence. No Redis → in-memory limiter. One failing feed does not stop the others.
* **Assumptions are visible.** Financial figures return the assumptions used (downtime days, exploit-probability rules).
* **Audit everything.** Writes queue ledger entries that are appended only after the transaction commits.

## II.4 How it works (workflows)

### 4.1 From feed to ranked risk

```mermaid
sequenceDiagram
    autonumber
    participant S as Scheduler (6h / on demand)
    participant F as Feed service
    participant N as NVD / KEV / EPSS
    participant M as Matcher
    participant R as Risk service
    participant DB as Database
    S->>F: feed_sync
    F->>N: fetch KEV catalogue
    F->>DB: upsert CVEs (commit)
    F->>N: NVD lookup for CVEs relevant to your assets<br/>(CVSS, CPE version ranges)
    F->>N: recent high/critical NVD CVEs
    F->>M: match CVE products ↔ asset software
    M->>M: name match, then version check<br/>(affected / not affected / unknown)
    M->>R: matches
    R->>DB: create risks, auto-close patched ones
    F->>N: EPSS for open risks
    R->>R: BWVS → freshness → trend → priority → Top-10
    R->>DB: scores, history, trend snapshot
```

### 4.2 Event → risk (SIEM path)

```mermaid
flowchart LR
    E[Event batch<br/>POST /logs/ingest] --> V{API key or<br/>analyst JWT?}
    V -- no --> X[401/403]
    V -- yes --> RES[Resolve asset<br/>by id / hostname / IP]
    RES --> STORE[(security_logs)]
    STORE --> CORR[Count correlated events<br/>last 24h per asset + category]
    CORR --> RISK[Create / escalate<br/>'threat activity' risk]
    RISK --> SCORE[Re-score → rank]
```

### 4.3 Multi-agent analysis

```mermaid
sequenceDiagram
    participant U as Analyst (UI)
    participant API as /agents/discussions/stream (SSE)
    participant EV as Evidence builder
    participant A as Analyst + Intel (parallel)
    participant FO as Forensics
    participant BU as Business
    participant RE as Response
    participant CO as Consensus
    U->>API: risk_id or incident_id
    API->>EV: gather facts: risk, CVE, asset, network, events, playbooks, history
    API-->>U: started
    EV->>A: evidence
    A-->>U: 2 messages (streamed)
    A->>FO: transcript so far
    FO-->>U: message
    FO->>BU: transcript
    BU-->>U: message
    BU->>RE: transcript
    RE-->>U: message
    RE->>CO: all 5 outputs
    CO-->>U: severity vote, agreement, dissent, prioritised actions, playbook
    CO->>API: persist discussion + ledger entry (evidence SHA-256)
```

Each agent receives the **same evidence pack** plus the discussion so far, must cite only that evidence, and answers
with strict JSON (message, severity, confidence, key points, recommendations, structured data). With Gemini configured
the agents are LLM-driven; otherwise each runs a deterministic rules function over the same evidence. If the LLM
fails mid-run the affected agent falls back to rules and is flagged `degraded`.

### 4.4 Risk → incident → playbook → closure

```mermaid
stateDiagram-v2
    [*] --> Active: risk created
    Active --> Investigating: Open incident
    Investigating --> Mitigating: Playbook started
    Mitigating --> Resolved: Playbook completed / incident closed
    Active --> Accepted: analyst accepts risk
    Resolved --> [*]
    Accepted --> [*]
    Active --> Resolved: auto-close (software patched)
```

Playbook executions advance automatically through *automated* steps and pause at *manual* steps until an analyst
marks them done or skips them; every step is written to the ledger.

## II.5 Core engines

### 5.1 BWVS — Business-Weighted Vulnerability Score

```
BWVS = 10 × ( 0.20·CVSS + 0.20·ExploitActivity + 0.15·Exposure
            + 0.20·AssetCriticality + 0.15·BusinessImpact + 0.10·AIRelevance )     (each term 0-10 → score 0-100)
```

| Component | Source | Scale |
| --- | --- | --- |
| CVSS | NVD | 0-10 |
| Exploit activity | KEV / Exploit-DB / Metasploit = 10, GitHub PoC = 8, other reports = 6, none = 2 | |
| Exposure | internet-facing 10 · VPN 7 · internal 4 · isolated 1 | |
| Asset criticality | payment/payroll 10 · core backend 8 · CRM/HR 6 · dev/test 3 | |
| Business impact | daily revenue impact: >₹10L = 10, 5-10L = 8, 1-5L = 6, <1L = 3 | |
| AI relevance | 90%+ = 10, 75% = 8, 50% = 6, 25% = 4, else 2 | |

Levels: **critical ≥ 80 · high ≥ 60 · medium ≥ 40 · low < 40**.

### 5.2 Dynamic ranking

```
Priority = BWVS × Freshness × Trend
Freshness = 0.5 ^ (days since last new evidence / 7)
Trend     = 1.0 … 2.0   (+0.40 KEV, +0.15 ransomware use, +0.10 public exploit,
                         +0.30×EPSS, +0.05…0.30 rising event volume)
```

### 5.3 Expected financial loss

```
P(asset compromised) = 1 − Π(1 − pᵢ)       pᵢ = EPSS (≥0.5 if KEV; 0.6 if seen in logs; CVSS prior otherwise) × exposure factor
Expected loss        = daily revenue impact × expected downtime days × P
```

### 5.4 Digital twin
Assets and connections form a directed graph (NetworkX). The engine provides BFS/DFS **attack paths**, **blast radius**,
**critical paths** (entry points → critical assets), and probabilistic **lateral-movement simulation** for
ransomware, APT, insider and DDoS scenarios, mapped to MITRE ATT&CK tactics, with downtime/loss from your inventory.

### 5.5 Audit ledger
```
data_hash  = SHA-256(payload)
block_hash = SHA-256(previous_hash + data_hash)
signature  = Ed25519(block_hash)
```
Verification checks every hash, every link, every signature, **and** that the displayed actor / event / resource columns
match the signed payload.

## II.6 Data model

```mermaid
erDiagram
    USERS ||--o{ INCIDENTS : creates
    USERS ||--o{ PLAYBOOK_EXECUTIONS : runs
    ASSETS ||--o{ RISKS : "has"
    ASSETS ||--o{ SECURITY_LOGS : "receives"
    ASSETS ||--o{ ASSET_CONNECTIONS : "source/target"
    CVES ||--o{ RISKS : "causes"
    RISKS ||--o{ RISK_SCORES : "score history"
    RISKS ||--o{ INCIDENTS : "escalates to"
    RISKS ||--o{ AGENT_DISCUSSIONS : "analysed by"
    INCIDENTS ||--o{ INCIDENT_ANALYSES : "agent output"
    INCIDENTS ||--o{ AGENT_DISCUSSIONS : "discussed in"
    PLAYBOOKS ||--o{ PLAYBOOK_EXECUTIONS : "instances"
    RISKS ||--o{ PLAYBOOK_EXECUTIONS : "remediated by"

    USERS {
        uuid id PK
        string email
        string role
        bool is_active
        int token_version
        json preferences
    }
    ASSETS {
        uuid id PK
        string name
        string hostname
        string ip_address
        string asset_type
        json software
        string exposure_level
        string criticality
        string network_zone
        string business_unit
        float daily_revenue_impact
        bool is_isolated
    }
    CVES {
        uuid id PK
        string cve_id UK
        float cvss_score
        bool cisa_kev
        bool has_exploit
        float epss_score
        json affected_software
        json version_ranges
        json cwes
    }
    RISKS {
        uuid id PK
        uuid cve_id FK
        uuid asset_id FK
        string source
        float bwvs_score
        float priority_score
        string status
        bool is_top_10
        datetime first_seen
        json match_reasons
    }
    RISK_SCORES {
        uuid id PK
        uuid risk_id FK
        float final_bwvs
        float cvss_score
        float exploit_activity
        float exposure_level
    }
    SECURITY_LOGS {
        uuid id PK
        uuid asset_id FK
        string category
        string severity
        string source_ip
        string status
        json raw_log
    }
    INCIDENTS {
        uuid id PK
        string ref
        uuid risk_id FK
        string status
        string severity
        json timeline
        json affected_assets
        string resolution
    }
    PLAYBOOKS {
        uuid id PK
        string slug
        string category
        json steps
        bool is_active
    }
    PLAYBOOK_EXECUTIONS {
        uuid id PK
        uuid playbook_id FK
        uuid risk_id FK
        uuid incident_id FK
        string status
        json step_results
    }
    AGENT_DISCUSSIONS {
        uuid id PK
        uuid risk_id FK
        uuid incident_id FK
        json messages
        json consensus
        string evidence_hash
    }
    ASSET_CONNECTIONS {
        uuid id PK
        uuid source_asset_id FK
        uuid target_asset_id FK
        string connection_type
        json protocols
    }
    LEDGER_BLOCKS {
        int block_number UK
        string previous_hash
        string data_hash
        string block_hash
        string signature
        string action_type
        string actor
    }
    RISK_SNAPSHOTS {
        datetime captured_at
        int open_total
        float avg_bwvs
        float exposure_lakhs
    }
    JOB_RUNS {
        string job_id
        string status
        json detail
    }
    REPORTS {
        uuid id PK
        string kind
        text content
        string generated_by
    }
    BLOCKED_INDICATORS {
        string indicator_type
        string value
        string reason
    }
    APP_SETTINGS {
        string key
        json value
    }
```

Schema is managed by Alembic (`backend/migrations`). 18 tables; development databases created by `create_all` gain new
nullable columns automatically.

## II.7 Security model

| Concern | Control |
| --- | --- |
| Authentication | bcrypt password hashes; short-lived JWT access + refresh tokens; `token_version` revokes all tokens on logout / role change / password change / disable; timing-equalised login |
| Authorisation | Role checks in the API (viewer < analyst < admin); every write endpoint verified in tests for viewer and anonymous callers |
| Brute force | Per-IP and per-account login throttles; global rate limit (Redis or memory); `X-Forwarded-For` trusted only when `TRUST_PROXY_HEADERS=true` |
| Injection | SQLAlchemy parameterised queries; strict Pydantic validation; UI renders data as text (no `innerHTML`) |
| SSRF | Webhook targets must resolve to public addresses; redirects disabled |
| Transport / browser | HSTS, CSP, `X-Frame-Options: DENY`, `nosniff`, no-referrer, explicit CORS origins |
| Secrets | Production refuses weak/default secrets, wildcard CORS, debug mode, short admin password; no secrets in the repo |
| Supply chain | Dependencies audited (`pip-audit` clean); non-root containers |
| Integrity | Signed hash-chain ledger with scheduled verification |

## II.8 Tech stack

| Layer | Choice | Why (short) |
| --- | --- | --- |
| API | **FastAPI** + Pydantic v2 | async I/O for feed calls and SSE streaming; typed validation; OpenAPI for free |
| ORM / DB | **SQLAlchemy 2 (async)**, **PostgreSQL** (SQLite in dev), **Alembic** | relational integrity, JSON columns, easy local dev, versioned schema |
| Cache | **Redis** (optional) | shared rate-limit counters across replicas |
| Scheduler | **APScheduler** | in-process cron/interval jobs with run history; no extra broker |
| Graph | **NetworkX** | pure-Python graph algorithms; enough for thousands of assets |
| AI | **Google Gemini** behind a small `AIClient` interface | JSON output, long context, generous free tier; swappable |
| Crypto | **Ed25519** + SHA-256 (`cryptography`) | small fast signatures, no parameter pitfalls |
| UI | **Next.js 16 / React 19**, **Tailwind**, **Recharts** | production build tooling, CSP/headers, small client |
| Packaging | Docker Compose (Postgres, Redis, API, web) | one-command deployment |

Detailed comparisons with alternatives are in **[Part I, section I.6](#i6-technology-stack--why-this-and-not-that)**.

## II.9 Getting started

### Local (SQLite, no Docker)
```bash
# Backend (Python 3.11+)
cd Horizon_Beach_Hacks-main/project_cyber/backend
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # set ADMIN_EMAIL / ADMIN_PASSWORD (10+ chars); optional GEMINI_API_KEY, NVD_API_KEY
uvicorn app.main:app --port 8000

# Frontend (Node 18+)
cd Horizon_Beach_Hacks-main/project_cyber/frontend
cp .env.example .env.local
npm install && npm run dev                            # http://localhost:3000
```

First steps in the UI: sign in → **Assets** (add/import, include software *with versions*) → wait for / run the feed
sync (**Settings → System**) → review **Top Risks** → run **AI analysis** or a **playbook**.
Connect your SIEM to `POST /api/v1/logs/ingest` to populate **Alerts**.

### Production (Docker Compose)
```bash
cd Horizon_Beach_Hacks-main/project_cyber
cp .env.example .env            # fill every REQUIRED value
docker compose up -d --build    # postgres + redis + api (runs alembic upgrade head) + web
```
Put a TLS-terminating reverse proxy in front; set `PUBLIC_API_URL`, `CORS_ORIGINS`, and `TRUST_PROXY_HEADERS=true`
only if the proxy is yours. Run **one** API replica (the scheduler runs in-process).

## II.10 Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `APP_ENV` | `development` / `test` / `production` | development |
| `SECRET_KEY`, `JWT_SECRET_KEY` | secrets (32+ chars in production) | — |
| `DATABASE_URL` | SQLAlchemy URL | SQLite file |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | first administrator | — |
| `GEMINI_API_KEY` | enables LLM agents/reports | unset → rules engine |
| `NVD_API_KEY` | higher NVD rate limit | unset |
| `NVD_ENRICH_PER_SYNC` | CVEs version-enriched per sync | 25 |
| `CVE_FETCH_INTERVAL_HOURS` | feed sync period | 6 |
| `RISK_CALCULATION_INTERVAL_MINUTES` | re-scoring period | 15 |
| `INGEST_API_KEY` | secret for SIEM → `/logs/ingest` | unset |
| `CORS_ORIGINS` | allowed web origins (JSON list) | localhost:3000 |
| `TRUST_PROXY_HEADERS` | honour `X-Forwarded-For` | false |
| `ALLOW_PRIVATE_WEBHOOKS` | permit internal webhook targets | false |
| `EXPECTED_DOWNTIME_DAYS_CRITICAL/DEFAULT` | loss-model assumptions | 3 / 1 |

## II.11 API
See **[Horizon_Beach_Hacks-main/API_DOCUMENTATION.md](Horizon_Beach_Hacks-main/API_DOCUMENTATION.md)** (generated from the OpenAPI schema). Interactive docs at `/docs`
outside production.

## II.12 Project structure

```
Horizon_Beach_Hacks-main/project_cyber/
├── docker-compose.yml          # Postgres + Redis + API + web
├── backend/
│   ├── app/
│   │   ├── main.py             # app, middleware, lifespan
│   │   ├── config.py           # settings + production validation
│   │   ├── api/routes/         # auth, risks, assets, alerts, incidents, playbooks, agents, twin, ledger, dashboard, admin, cves
│   │   ├── services/           # business logic (risk, feed, matcher, playbook, dashboard, report, ledger …)
│   │   ├── risk_engine/        # BWVS + ranking
│   │   ├── agents/             # 5 agents, evidence builder, orchestrator
│   │   ├── twin/               # digital-twin graph engine
│   │   ├── ledger/             # event types, Ed25519 signing
│   │   ├── ingestion/          # CISA / NVD / EPSS collector
│   │   ├── ai/                 # Gemini client
│   │   ├── models/ schemas/    # SQLAlchemy models, Pydantic schemas
│   │   ├── workers/            # APScheduler jobs
│   │   └── auth/ utils/        # JWT, passwords, rate limit, network helpers
│   ├── playbooks/              # 5 response playbooks (JSON)
│   ├── migrations/             # Alembic
│   └── tests/                  # 100+ unit, API and security tests
└── frontend/
    ├── app/                    # routes: / and /login
    ├── components/             # views + dashboard widgets + modals
    ├── lib/api/                # typed API client (auth refresh, SSE)
    ├── contexts/ hooks/        # auth, theme, data hooks
    └── next.config.js          # security headers, standalone output
```

## II.13 Testing
```bash
cd Horizon_Beach_Hacks-main/project_cyber/backend && pytest                       # scoring, ledger, API workflows, version matching, security
cd Horizon_Beach_Hacks-main/project_cyber/frontend && npx tsc --noEmit && npm run build
```

## II.14 Known limitations
* CISA KEV carries no version data; version confirmation depends on NVD lookups (rate-limited without an NVD key), so many matches show *version not verified* until enriched.
* Ledger signing key lives beside the database; export the ledger periodically or keep the key in a secrets manager for strong non-repudiation.
* Webhook delivery, containment actions and SSO are integration points, not bundled connectors.
* AI output is advisory; agents are read-only and never change data.
* Single API replica (in-process scheduler).
