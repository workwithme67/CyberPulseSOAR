# SOAR Incident Containment Engine

> **Security Orchestration, Automation, and Response (SOAR) Platform**
> Internship project — backend milestone with alerting, scoring, timeline, and playbook automation.

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-orange)](https://sqlalchemy.org)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)](#testing)
[![Milestone](https://img.shields.io/badge/Milestone-50%25-blue)](#features-completed)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Database Schema](#database-schema)
5. [Installation Guide](#installation-guide)
6. [Configuration](#configuration)
7. [API Documentation](#api-documentation)
8. [Risk Scoring Engine](#risk-scoring-engine)
9. [Threat Intelligence Module](#threat-intelligence-module)
10. [Incident Timeline System](#incident-timeline-system)
11. [Dashboard Analytics](#dashboard-analytics)
12. [Testing](#testing)
13. [Features Completed (50%)](#features-completed)
14. [Future Scope (Remaining 50%)](#future-scope)
15. [Project Structure](#project-structure)

---

## Project Overview

The **SOAR Incident Containment Engine** is a FastAPI backend for automating the detection, enrichment, scoring, and triage of cybersecurity incidents.

This backend is intentionally structured around small, testable layers so the alert pipeline stays easy to extend:

When a security alert is ingested, the engine automatically:
1. **Validates** the source IP and input data.
2. **Enriches** the IP through AbuseIPDB and VirusTotal.
3. **Calculates** a weighted risk score in the 0–100 range.
4. **Records** a full incident timeline for audit purposes.
5. **Exposes** dashboard analytics for operational visibility.

## Project Notes

- The API is designed around FastAPI, SQLAlchemy, and Pydantic v2.
- Playbooks live at the repository root and are loaded dynamically by name.
- The current milestone keeps threat intelligence integrations mock-friendly so the backend works without API keys.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SOAR Incident Containment Engine                │
│                          [50% Milestone]                            │
└─────────────────────────────────────────────────────────────────────┘

  HTTP Client / Swagger UI
         │
         ▼
  ┌─────────────┐
  │  FastAPI    │  ◄── app/main.py
  │  (ASGI)     │      • CORS middleware
  └──────┬──────┘      • OpenAPI documentation
         │
  ┌──────▼───────────────────────────────┐
  │           Routers (Routes Layer)     │
  │  ┌────────────────┐ ┌─────────────┐ │
  │  │  alerts.py     │ │ dashboard.py│ │
  │  │  POST /alerts  │ │ GET /summary│ │
  │  │  GET  /alerts  │ │ GET /risk-  │ │
  │  │  GET  /{id}    │ │     distrib │ │
  │  │  PATCH /status │ │ GET /recent │ │
  │  │  DELETE /{id}  │ └─────────────┘ │
  │  │  GET /enrich   │                 │
  │  │  GET /timeline │                 │
  │  └───────┬────────┘                 │
  └──────────┼───────────────────────────┘
             │
  ┌──────────▼───────────────────────────┐
  │         Service Layer                │
  │  ┌─────────────────┐                 │
  │  │  alert_service  │ ← orchestrates  │
  │  └────┬────┬───────┘   all below     │
  │       │    │                         │
  │  ┌────▼──┐ ┌▼───────────────────┐   │
  │  │threat_│ │   risk_scoring.py  │   │
  │  │intel- │ │ • SEVERITY_WEIGHTS │   │
  │  │ligence│ │ • ALERT_TYPE_WTS   │   │
  │  │.py    │ │ • TI score factor  │   │
  │  │       │ │ • Off-hours factor │   │
  │  │AbuseIP│ └────────────────────┘   │
  │  │DB     │                          │
  │  │Virus  │  ┌──────────────────┐    │
  │  │Total  │  │timeline_service  │    │
  │  └───────┘  │ • add_event()    │    │
  │             │ • get_timeline() │    │
  │             └──────────────────┘    │
  └──────────────────────┬──────────────┘
                         │
  ┌──────────────────────▼──────────────┐
  │         Database Layer (SQLAlchemy) │
  │                                     │
  │  ┌─────────────┐  ┌───────────────┐ │
  │  │   alerts    │  │timeline_events│ │
  │  │  (ORM Model)│◄─│   (ORM Model) │ │
  │  └─────────────┘  └───────────────┘ │
  │           SQLite (dev) / PostgreSQL  │
  └─────────────────────────────────────┘
```

### Request Flow: Alert Ingestion

```
POST /alerts/
     │
     ▼
[1] Pydantic Validation
     │  • IPv4 check
     │  • Severity enum
     │
     ▼
[2] Persist Alert Skeleton (DB)
     │
     ▼
[3] Timeline: AlertCreated
     │
     ▼
[4] Threat Intelligence Enrichment
     │  • AbuseIPDB lookup (real/mock)
     │  • VirusTotal lookup (real/mock)
     │  • Aggregate confidence score
     │  • Verdict: Clean | Suspicious | Malicious
     │
     ▼
[5] Timeline: AlertEnriched
     │
     ▼
[6] Risk Score Calculation
     │  score = sev_weight + type_weight + ti_weight + off_hrs_penalty
     │
     ▼
[7] Timeline: RiskCalculated
     │
     ▼
[8] Update Alert (risk_score, threat_verdict, enrichment_data)
     │
     ▼
[9] Return AlertResponse (HTTP 201)
```

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Web Framework | FastAPI | 0.111.0 |
| ASGI Server | Uvicorn | 0.30.1 |
| Data Validation | Pydantic v2 | 2.7.1 |
| ORM | SQLAlchemy | 2.0.30 |
| Database | SQLite (dev) | built-in |
| Migrations | Alembic | 1.13.1 |
| HTTP Client | Requests | 2.32.3 |
| Config | pydantic-settings | 2.3.0 |
| Testing | pytest + httpx | 8.2.2 / 0.27.0 |
| Python | CPython | 3.11+ |

---

## Database Schema

### `alerts` table

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER PK | No | Auto-increment integer primary key |
| `alert_id` | VARCHAR(50) UNIQUE | No | Human-readable ID (ALERT-XXXXXXXX) |
| `alert_type` | VARCHAR(100) | No | Category (Brute Force, Port Scan, …) |
| `source_ip` | VARCHAR(45) | No | IPv4 address that triggered the alert |
| `severity` | ENUM | No | Low \| Medium \| High \| Critical |
| `status` | ENUM | No | Open \| Investigating \| Resolved |
| `description` | VARCHAR(500) | Yes | Optional context |
| `risk_score` | FLOAT | Yes | Computed score 0.0–100.0 |
| `threat_verdict` | VARCHAR(20) | Yes | Clean \| Suspicious \| Malicious |
| `enrichment_data` | TEXT (JSON) | Yes | Full TI enrichment report |
| `created_at` | DATETIME | No | UTC timestamp of ingestion |
| `updated_at` | DATETIME | No | UTC timestamp of last update |

### `timeline_events` table

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER PK | No | Auto-increment primary key |
| `alert_db_id` | INTEGER FK→alerts.id | No | Parent alert (CASCADE DELETE) |
| `alert_id` | VARCHAR(50) | No | Denormalised alert_id for direct queries |
| `event_type` | ENUM | No | AlertCreated \| AlertEnriched \| RiskCalculated \| StatusUpdated \| AlertDeleted |
| `description` | VARCHAR(500) | No | Human-readable event description |
| `metadata_json` | TEXT (JSON) | Yes | Extra context (old/new status, TI snapshot, …) |
| `occurred_at` | DATETIME | No | UTC timestamp of the event |

### Entity Relationship

```
alerts (1) ──── (N) timeline_events
  │                      │
  id ─────────── alert_db_id (FK, CASCADE DELETE)
  alert_id ─── alert_id (denormalised)
```

---

## Installation Guide

### Prerequisites

- Python 3.11+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/workwithme67/soar-incident-containment-engine.git
cd "soar-incident-containment-engine/backend"
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
copy .env.example .env     # Windows
cp .env.example .env       # Linux/macOS
```

Edit `.env` to set your API keys (optional — mock data is used without keys):

```env
DATABASE_URL=sqlite:///./soar.db
ABUSEIPDB_API_KEY=your-key-here      # Leave empty for mock
VIRUSTOTAL_API_KEY=your-key-here     # Leave empty for mock
LOG_LEVEL=INFO
```

### 5. Start the server

```bash
uvicorn app.main:app --reload
```

### 6. Open the API docs

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Configuration

All settings are managed via `app/config.py` using Pydantic Settings.
Values are loaded from environment variables → `.env` file → defaults.

| Setting | Default | Description |
|---------|---------|-------------|
| `APP_ENV` | `development` | Environment tag |
| `DATABASE_URL` | `sqlite:///./soar.db` | Database connection string |
| `LOG_LEVEL` | `INFO` | Console log level |
| `LOG_FILE` | `soar.log` | Rotating log file path |
| `LOG_MAX_BYTES` | `10485760` | Max log file size (10 MB) |
| `LOG_BACKUP_COUNT` | `5` | Old log files to keep |
| `ABUSEIPDB_API_KEY` | `""` | Real AbuseIPDB key (empty = mock) |
| `VIRUSTOTAL_API_KEY` | `""` | Real VirusTotal key (empty = mock) |
| `TI_REQUEST_TIMEOUT` | `10` | TI API timeout in seconds |
| `TI_MAX_DAYS_CHECK` | `90` | AbuseIPDB lookback window (days) |

---

## API Documentation

Base URL: `http://localhost:8000`
Interactive Docs: `http://localhost:8000/docs`

### Alert Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/alerts/` | Create and enrich a new alert |
| `GET` | `/alerts/` | List alerts (filters + pagination) |
| `GET` | `/alerts/{id}` | Get single alert by integer ID |
| `PATCH` | `/alerts/{id}/status` | Update workflow status |
| `DELETE` | `/alerts/{id}` | Delete alert and all timeline events |
| `GET` | `/alerts/{id}/enrich` | Get live TI enrichment for the alert |
| `GET` | `/alerts/{id}/timeline` | Get full incident lifecycle timeline |

### Dashboard Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | Aggregate counts by status, severity, verdict |
| `GET` | `/dashboard/risk-distribution` | Risk score histogram (4 bands) |
| `GET` | `/dashboard/recent-alerts` | Most recent N alerts |

### Health Endpoint

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check with version and TI mode |

---

### Request / Response Examples

#### POST /alerts/ — Create Alert

**Request:**
```json
{
  "alert_type": "Brute Force",
  "source_ip": "203.0.113.42",
  "severity": "High",
  "description": "SSH brute-force attack detected from external IP."
}
```

**Response (201):**
```json
{
  "id": 1,
  "alert_id": "ALERT-A3F80001",
  "alert_type": "Brute Force",
  "source_ip": "203.0.113.42",
  "severity": "High",
  "status": "Open",
  "description": "SSH brute-force attack detected from external IP.",
  "risk_score": 76.0,
  "threat_verdict": "Malicious",
  "created_at": "2026-06-22T08:30:00Z",
  "updated_at": "2026-06-22T08:30:00Z"
}
```

#### GET /dashboard/summary

**Response (200):**
```json
{
  "total_alerts": 42,
  "open_alerts": 18,
  "investigating_alerts": 14,
  "resolved_alerts": 10,
  "critical_alerts": 6,
  "high_alerts": 12,
  "medium_alerts": 15,
  "low_alerts": 9,
  "malicious_ips": 8,
  "suspicious_ips": 11,
  "avg_risk_score": 54.3
}
```

#### GET /alerts/{id}/timeline

**Response (200):**
```json
{
  "alert_id": "ALERT-A3F80001",
  "alert_type": "Brute Force",
  "source_ip": "203.0.113.42",
  "severity": "High",
  "status": "Investigating",
  "risk_score": 76.0,
  "threat_verdict": "Malicious",
  "created_at": "2026-06-22T08:30:00Z",
  "events": [
    {
      "id": 1,
      "event_type": "AlertCreated",
      "description": "Alert ingested | type=Brute Force ip=203.0.113.42 severity=High",
      "occurred_at": "2026-06-22T08:30:00Z"
    },
    {
      "id": 2,
      "event_type": "AlertEnriched",
      "description": "TI enrichment complete | verdict=Malicious confidence=82.0",
      "occurred_at": "2026-06-22T08:30:01Z"
    },
    {
      "id": 3,
      "event_type": "RiskCalculated",
      "description": "Risk score computed | score=76.0 level=Critical",
      "occurred_at": "2026-06-22T08:30:01Z"
    },
    {
      "id": 4,
      "event_type": "StatusUpdated",
      "description": "Status changed: Open -> Investigating",
      "occurred_at": "2026-06-22T08:45:00Z"
    }
  ]
}
```

---

## Risk Scoring Engine

Location: `app/services/risk_scoring.py`

The engine computes a weighted numeric score in **[0, 100]** from four factors:

| Factor | Max Points | Description |
|--------|-----------|-------------|
| Severity | 40 | Low=10, Medium=20, High=30, Critical=40 |
| Alert Type | 30 | Known-dangerous types score higher |
| Threat Intelligence | 20 | TI aggregate confidence × 20 |
| Off-hours Penalty | 10 | Attacks 00:00–06:00 UTC |

**Score → Risk Level:**

| Score | Level | Indicator |
|-------|-------|-----------|
| 0–25 | Low | 🟢 |
| 26–50 | Medium | 🟡 |
| 51–75 | High | 🟠 |
| 76–100 | Critical | 🔴 |

**Alert type weights (selected):**

| Alert Type | Points |
|------------|--------|
| Ransomware | 30 |
| Zero-Day Exploit | 30 |
| SQL Injection | 25 |
| C2 Communication | 27 |
| Brute Force | 20 |
| Port Scan | 12 |

---

## Threat Intelligence Module

Location: `app/services/threat_intelligence.py`

### Priority Mode

| API Key Set? | Mode |
|-------------|------|
| `ABUSEIPDB_API_KEY` is configured | Real API call to `api.abuseipdb.com/api/v2/check` |
| No key | Deterministic mock (same IP → same data every run) |
| `VIRUSTOTAL_API_KEY` is configured | Real API call to `www.virustotal.com/api/v3/ip_addresses/{ip}` |
| No key | Deterministic mock |

### Aggregate Confidence Formula

```
aggregate_confidence =
    (AbuseIPDB_confidence_score × 0.6)
  + (VirusTotal_malicious_ratio × 100 × 0.4)
```

### Verdict Thresholds

| Aggregate | Verdict |
|-----------|---------|
| ≥ 60 | Malicious |
| ≥ 25 | Suspicious |
| < 25 | Clean |

---

## Incident Timeline System

Every alert has a complete audit trail of lifecycle events stored in
the `timeline_events` table. Events are created automatically by the service layer.

### Event Types

| Event | Trigger |
|-------|---------|
| `AlertCreated` | Alert is ingested via POST /alerts/ |
| `AlertEnriched` | TI lookup completes |
| `RiskCalculated` | Risk score is computed |
| `StatusUpdated` | PATCH /alerts/{id}/status is called |
| `AlertDeleted` | DELETE /alerts/{id} is called |

### Timeline API

```
GET /alerts/{id}/timeline
```

Returns all events in chronological order (oldest first) with optional
JSON metadata payload per event.

---

## Dashboard Analytics

### GET /dashboard/summary

Real-time aggregate counts:
- Total, Open, Investigating, Resolved alerts
- Critical, High, Medium, Low by severity
- Malicious, Suspicious IPs (by threat verdict)
- Average risk score across all alerts

### GET /dashboard/risk-distribution

Risk score histogram with 4 bands:
```json
{
  "total": 42,
  "buckets": [
    {"label": "Low",      "range": "0-25",   "count": 9,  "pct": 21.4},
    {"label": "Medium",   "range": "26-50",  "count": 15, "pct": 35.7},
    {"label": "High",     "range": "51-75",  "count": 12, "pct": 28.6},
    {"label": "Critical", "range": "76-100", "count": 6,  "pct": 14.3}
  ]
}
```

### GET /dashboard/recent-alerts

Most recent N alerts (default 10, max 50).

---

## Testing

### Run all tests

```bash
python -m pytest tests/ -v
```

### Test suites

| File | Tests | Coverage |
|------|-------|----------|
| `tests/test_alerts.py` | 81 | Alert CRUD, validation, TI, risk scoring |
| `tests/test_dashboard.py` | 25 | Summary, risk distribution, recent alerts |
| `tests/test_timeline.py` | 30 | Timeline events, delete cascade, service units |
| **Total** | **~136** | Full backend coverage |

### Test Architecture

All tests use:
- **In-memory SQLite** (`sqlite://` + `StaticPool`) — no file I/O, no cleanup required.
- **FastAPI TestClient** — real HTTP request/response cycle.
- **Isolated `setup_database` fixture** — fresh DB per test class.

---

## Features Completed

### ✅ 50% Milestone Deliverables

| Feature | Status | Details |
|---------|--------|---------|
| FastAPI Project Setup | ✅ Complete | Production config, logging, CORS |
| Database Layer | ✅ Complete | SQLAlchemy, SQLite, migrations |
| Alert Model | ✅ Complete | All fields + enums + relationships |
| Create Alert | ✅ Complete | POST /alerts/ with full pipeline |
| Get All Alerts | ✅ Complete | Pagination + filtering |
| Get Alert By ID | ✅ Complete | With 404 handling |
| Update Alert Status | ✅ Complete | PATCH with timeline event |
| Delete Alert | ✅ Complete | CASCADE timeline delete |
| IPv4 Validation | ✅ Complete | Strict IPv4-only validation |
| Severity Validation | ✅ Complete | Enum + case-insensitive |
| Input Sanitisation | ✅ Complete | Pydantic v2 validators |
| AbuseIPDB Integration | ✅ Complete | Real API + deterministic mock |
| VirusTotal Integration | ✅ Complete | Real API + deterministic mock |
| Threat Enrichment | ✅ Complete | Auto-run on alert creation |
| Risk Scoring Engine | ✅ Complete | 4-factor weighted score |
| Risk Levels | ✅ Complete | Low / Medium / High / Critical |
| Dashboard Summary | ✅ Complete | GET /dashboard/summary |
| Risk Distribution | ✅ Complete | GET /dashboard/risk-distribution |
| Recent Alerts | ✅ Complete | GET /dashboard/recent-alerts |
| Incident Timeline | ✅ Complete | 5 event types, chronological |
| Timeline API | ✅ Complete | GET /alerts/{id}/timeline |
| Swagger Documentation | ✅ Complete | All endpoints with examples |
| Unit Tests | ✅ Complete | ~136 tests, all passing |
| Logging | ✅ Complete | Console + rotating file handler |
| Environment Config | ✅ Complete | Pydantic Settings + .env |
| Documentation | ✅ Complete | This README |

---

## Future Scope

### Remaining 50% — Planned Features

| Feature | Priority | Description |
|---------|----------|-------------|
| **Frontend Dashboard** | High | React/Next.js real-time dashboard with charts |
| **User Authentication** | High | JWT-based auth + RBAC (Admin, Analyst, Viewer) |
| **Playbook Automation** | High | Rule-based response playbooks (auto-block IP, send alert) |
| **Real-time Notifications** | Medium | WebSocket push for new Critical alerts |
| **SIEM Integration** | Medium | Splunk / Elastic SIEM webhook forwarding |
| **PostgreSQL Migration** | Medium | Production DB with Alembic migrations |
| **Containerisation** | Medium | Dockerfile + docker-compose.yml |
| **CI/CD Pipeline** | Low | GitHub Actions: test → lint → build → deploy |
| **Rate Limiting** | Low | API throttling per client IP |
| **Export / Reporting** | Low | PDF/CSV report generation |

---

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app, routers, lifespan
│   ├── config.py                  # Pydantic Settings
│   ├── database/
│   │   ├── __init__.py
│   │   └── db.py                  # Engine, session factory, Base
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py               # Alert ORM model + enums
│   │   ├── schemas.py             # All Pydantic schemas
│   │   └── timeline.py            # TimelineEvent ORM model
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── alerts.py              # /alerts/* endpoints
│   │   └── dashboard.py           # /dashboard/* endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   ├── alert_service.py       # Alert CRUD + orchestration
│   │   ├── risk_scoring.py        # Risk scoring engine
│   │   ├── threat_intelligence.py # AbuseIPDB + VirusTotal
│   │   └── timeline_service.py    # Timeline event CRUD
│   └── utils/
│       ├── __init__.py
│       └── helpers.py             # Logger factory + setup_logging()
├── tests/
│   ├── __init__.py
│   ├── seed_data.py               # Sample data for manual testing
│   ├── test_alerts.py             # 81 alert tests
│   ├── test_dashboard.py          # 25 dashboard tests
│   └── test_timeline.py           # 30 timeline tests
├── .env.example                   # Environment variable template
├── .gitignore
├── README.md
└── requirements.txt
```

---

*SOAR Incident Containment Engine — Infotact Internship Project*
*Backend 50% Milestone Complete*



**By: Jigyasu Labana**
