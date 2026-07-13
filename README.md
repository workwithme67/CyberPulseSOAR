# 🛡️ SOAR Incident Containment Engine

> **Security Orchestration, Automation, and Response (SOAR) Platform**  
> Cybersecurity internship project for automated incident containment and response.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-orange?logo=python)](https://sqlalchemy.org)
[![Tests](https://img.shields.io/badge/Tests-136%20Passing-brightgreen?logo=pytest)](./backend/tests)
[![Milestone](https://img.shields.io/badge/Backend-100%25%20Complete-blue)](#-features-completed)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 📖 Overview

The **SOAR Incident Containment Engine** is a cybersecurity automation platform for ingesting alerts, enriching them with threat intelligence, computing weighted risk scores, executing response playbooks, and keeping a full incident audit trail through a clean REST API.

The repository is split into a backend API in `backend/` and reusable playbooks in `playbooks/`. The root README focuses on the full project vision, while the backend README covers implementation details and local setup.

### Current focus

- Alert ingestion, enrichment, risk scoring, and timeline tracking.
- Automated response playbooks for blocking, isolating, notifying, and escalating.
- FastAPI endpoints for dashboards and incident operations.
- A backend codebase that is ready for further authentication and frontend work.

### What it does, end-to-end:

```
Security Alert Received
        │
        ▼
  [1] Validate & Ingest ──► IPv4 check, severity enum, Pydantic v2
        │
        ▼
  [2] Threat Intelligence ──► AbuseIPDB + VirusTotal (real / mock)
        │
        ▼
  [3] Risk Scoring ──────────► 4-factor weighted score (0–100)
        │
        ▼
  [4] Timeline Recorded ─────► Full audit trail per incident
        │
        ▼
  [5] Playbook Execution ─────► block_ip / isolate_host / notify_soc / escalate
        │
        ▼
  [6] Dashboard Analytics ────► Real-time summary, risk distribution, recent alerts
```

---

## ✨ Features

| Feature | Status | Details |
|---------|--------|---------|
| 🚨 Alert Ingestion & Management | ✅ Complete | Full CRUD with pagination & filtering |
| 🔍 Threat Intelligence Enrichment | ✅ Complete | AbuseIPDB + VirusTotal (real API + deterministic mock) |
| 📊 Risk Scoring Engine | ✅ Complete | 4-factor weighted score (0–100) |
| 🎭 Automated Response Playbooks | ✅ Complete | block_ip, isolate_host, notify_soc, escalate |
| 📅 Incident Timeline Tracking | ✅ Complete | 5 event types, full audit trail |
| 📈 Interactive Dashboard API | ✅ Complete | Summary, risk distribution, recent alerts |
| 🔐 User Authentication (RBAC) | 🔜 In Progress | JWT-based auth + Admin/Analyst/Viewer roles |
| 🌐 Frontend Dashboard | ✅ Complete | React/Vite real-time dashboard |
| 📧 Real-time Notifications | 🔜 Planned | WebSocket push for Critical alerts |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SOAR Incident Containment Engine                  │
└─────────────────────────────────────────────────────────────────────┘

  HTTP Client / Swagger UI
         │
         ▼
  ┌─────────────┐
  │   FastAPI   │  ◄── app/main.py  (CORS + OpenAPI)
  └──────┬──────┘
         │
  ┌──────▼────────────────────────────────┐
  │           Routes Layer                │
  │  alerts.py   │  dashboard.py          │
  └──────┬────────────────────────────────┘
         │
  ┌──────▼────────────────────────────────┐
  │           Service Layer               │
  │  alert_service  →  orchestration      │
  │  threat_intelligence  →  AbuseIPDB    │
  │                         VirusTotal    │
  │  risk_scoring    →  4-factor score    │
  │  timeline_service →  audit events     │
  └──────┬────────────────────────────────┘
         │
  ┌──────▼────────────────────────────────┐
  │  Playbooks Layer                      │
  │  block_ip.py  │  isolate_host.py      │
  │  notify_soc.py│  escalate.py          │
  └──────┬────────────────────────────────┘
         │
  ┌──────▼────────────────────────────────┐
  │  Database Layer (SQLAlchemy)           │
  │  alerts table  ←→  timeline_events    │
  │  SQLite (dev) / PostgreSQL (prod)      │
  └───────────────────────────────────────┘
```

---

## 🧩 Tech Stack

### Backend

| Layer | Technology | Version |
|-------|-----------|---------|
| Web Framework | FastAPI | 0.111.0 |
| ASGI Server | Uvicorn | 0.30.1 |
| Data Validation | Pydantic v2 | 2.7.1 |
| ORM | SQLAlchemy | 2.0.30 |
| Config | pydantic-settings | 2.3.0 |
| HTTP Client | Requests | 2.32.3 |
| Testing | pytest + httpx | latest |
| Python | CPython | 3.11+ |

### Database

| Environment | Database |
|-------------|----------|
| Development | SQLite (built-in) |
| Production | PostgreSQL (planned) |

### Threat Intelligence APIs

| API | Purpose |
|-----|---------|
| [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation & abuse confidence |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine malware/IP analysis |
| [IPInfo](https://ipinfo.io/) | Geolocation & ASN data (planned) |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/workwithme67/soar-incident-containment-engine.git
cd soar-incident-containment-engine/backend
```

### 2. Create & activate virtual environment

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

Edit `.env` (API keys are optional — mock data is used without keys):

```env
DATABASE_URL=sqlite:///./soar.db
ABUSEIPDB_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
LOG_LEVEL=INFO
```

### 5. Start the server

```bash
uvicorn app.main:app --reload
```

### 6. Open API docs

| Interface | URL |
|-----------|-----|
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/ |

---

## 📡 API Reference

### Alert Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/alerts/` | Create & auto-enrich a new alert |
| `GET` | `/alerts/` | List alerts (filters + pagination) |
| `GET` | `/alerts/{id}` | Get single alert by ID |
| `PATCH` | `/alerts/{id}/status` | Update workflow status |
| `DELETE` | `/alerts/{id}` | Delete alert + cascade timeline |
| `GET` | `/alerts/{id}/enrich` | Fetch live TI enrichment |
| `GET` | `/alerts/{id}/timeline` | Full incident lifecycle timeline |

### Dashboard Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | Aggregate counts by status/severity/verdict |
| `GET` | `/dashboard/risk-distribution` | Risk score histogram (4 bands) |
| `GET` | `/dashboard/recent-alerts` | Most recent N alerts |

### Example: Create Alert

```bash
curl -X POST http://localhost:8000/alerts/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_type": "Brute Force",
    "source_ip": "203.0.113.42",
    "severity": "High",
    "description": "SSH brute-force attack detected from external IP."
  }'
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
  "risk_score": 76.0,
  "threat_verdict": "Malicious",
  "created_at": "2026-06-29T08:30:00Z"
}
```

---

## 🎯 Risk Scoring Engine

A weighted 4-factor formula computes scores in **[0, 100]**:

| Factor | Max Points | Logic |
|--------|-----------|-------|
| Severity | 40 | Low=10, Medium=20, High=30, Critical=40 |
| Alert Type | 30 | Ransomware/Zero-Day=30, Brute Force=20, Port Scan=12 |
| Threat Intelligence | 20 | TI aggregate confidence × 20 |
| Off-hours Penalty | 10 | Attacks between 00:00–06:00 UTC |

**Risk Levels:**

| Score | Level | Indicator |
|-------|-------|-----------|
| 0–25 | Low | 🟢 |
| 26–50 | Medium | 🟡 |
| 51–75 | High | 🟠 |
| 76–100 | Critical | 🔴 |

---

## 🤖 Automated Playbooks

Located in `playbooks/`, these scripts execute automated containment actions:

| Playbook | File | Action |
|----------|------|--------|
| Block IP | `block_ip.py` | Firewall rule to block malicious source IP |
| Isolate Host | `isolate_host.py` | Network isolation of compromised host |
| Notify SOC | `notify_soc.py` | Alert SOC team via email/webhook |
| Escalate | `escalate.py` | Escalate critical incidents to senior analysts |

Playbooks are triggered automatically based on risk score thresholds and threat verdict.

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=app --cov-report=term-missing
```

| Test Suite | Tests | Coverage |
|-----------|-------|----------|
| `test_alerts.py` | 81 | Alert CRUD, validation, TI enrichment, risk scoring |
| `test_dashboard.py` | 25 | Summary, risk distribution, recent alerts |
| `test_timeline.py` | 30 | Timeline events, delete cascade, service units |
| **Total** | **~136** | Full backend coverage |

All tests use **in-memory SQLite** + **FastAPI TestClient** — zero external dependencies required.

---

## 📁 Project Structure

```
soar-incident-containment-engine/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app, routers, lifespan
│   │   ├── config.py                  # Pydantic Settings
│   │   ├── database/
│   │   │   └── db.py                  # Engine, session factory, Base
│   │   ├── models/
│   │   │   ├── alert.py               # Alert ORM model + enums
│   │   │   ├── schemas.py             # All Pydantic schemas
│   │   │   └── timeline.py            # TimelineEvent ORM model
│   │   ├── routes/
│   │   │   ├── alerts.py              # /alerts/* endpoints
│   │   │   └── dashboard.py           # /dashboard/* endpoints
│   │   └── services/
│   │       ├── alert_service.py       # Alert CRUD + orchestration
│   │       ├── risk_scoring.py        # Risk scoring engine
│   │       ├── threat_intelligence.py # AbuseIPDB + VirusTotal
│   │       └── timeline_service.py    # Timeline event CRUD
│   ├── tests/
│   │   ├── test_alerts.py             # 81 alert tests
│   │   ├── test_dashboard.py          # 25 dashboard tests
│   │   └── test_timeline.py           # 30 timeline tests
│   ├── .env.example
│   ├── requirements.txt
│   └── README.md                      # Backend-specific docs
├── frontend/
│   ├── src/
│   │   ├── App.tsx                    # Live SOAR dashboard UI
│   │   ├── main.tsx                   # React entrypoint
│   │   └── styles.css                 # Dashboard styling
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── README.md                      # Frontend-specific docs
├── playbooks/
│   ├── block_ip.py                    # Block malicious IPs
│   ├── isolate_host.py                # Host isolation
│   ├── notify_soc.py                  # SOC notification
│   └── escalate.py                    # Incident escalation
└── README.md                          # ← You are here
```

---

## 🔮 Roadmap

| Feature | Priority | Status |
|---------|----------|--------|
| Frontend Dashboard (React/Vite) | ✅ Complete | Live dashboard consuming backend analytics |
| JWT Auth + RBAC | 🔴 High | In Progress |
| WebSocket Real-time Alerts | 🟡 Medium | Planned |
| SIEM Integration (Splunk/Elastic) | 🟡 Medium | Planned |
| PostgreSQL Migration | 🟡 Medium | Planned |
| Docker + docker-compose | 🟡 Medium | Planned |
| GitHub Actions CI/CD | 🟢 Low | Planned |
| PDF/CSV Report Export | 🟢 Low | Planned |
| MITRE ATT&CK Mapping | 🟢 Low | Planned |
| Rate Limiting | 🟢 Low | Planned |

---

## 👤 Author

**Jigyasu Labana**

- 🌐 Portfolio: [jigyasulabanaportfolio.vercel.app](https://jigyasulabanaportfolio.vercel.app/)
- 🏢 Internship: Cyber Security Internship — Infotact Solution

---

## 📄 License

This project is licensed under the MIT License.

---

*SOAR Incident Containment Engine — Built with ❤️ during Infotact Internship*
