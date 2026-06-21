"""
SOAR Incident Containment Engine – Main Application Entry Point. Day 2.

Changes from Day 1
------------------
- Added structured logging configuration.
- Added /health endpoint with version and uptime info.
- Added /risk-scores endpoint summarising scoring bands.
"""

import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.db import engine, Base
from app.routes import alerts


# ── Logging configuration ────────────────────────────────────────────────────
def configure_logging() -> None:
    """Set up structured console logging for the application."""
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quieten noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


configure_logging()
logger = logging.getLogger("soar.main")

# ── Application start time ────────────────────────────────────────────────────
_START_TIME = datetime.now(timezone.utc)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialised OK")
    logger.info("SOAR Engine is ready.")
    yield
    logger.info("SOAR Engine shutting down.")


# ── Application factory ───────────────────────────────────────────────────────
app = FastAPI(
    title="SOAR Incident Containment Engine",
    description=(
        "## Security Orchestration, Automation, and Response Platform\n\n"
        "**Day 2** – Alert management workflow, threat intelligence enrichment "
        "(mock), and risk scoring engine.\n\n"
        "### Key Features\n"
        "- Ingest security alerts with IPv4 validation\n"
        "- Automatic threat intelligence enrichment (AbuseIPDB + VirusTotal)\n"
        "- Dynamic risk scoring (0-100) with 4-band categorisation\n"
        "- Workflow status management (OPEN → INVESTIGATING → RESOLVED)\n"
        "- Paginated, filterable alert listings\n\n"
        "### Risk Score Bands\n"
        "| Score | Category |\n"
        "|-------|----------|\n"
        "| 0-25  | Low      |\n"
        "| 26-50 | Medium   |\n"
        "| 51-75 | High     |\n"
        "| 76-100| Critical |"
    ),
    version="0.2.0",
    contact={"name": "Infotact Internship – SOAR Team"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="Health check")
def health_check() -> dict:
    """Root health-check endpoint."""
    uptime_seconds = (datetime.now(timezone.utc) - _START_TIME).total_seconds()
    return {
        "status": "running",
        "project": "SOAR Incident Containment Engine",
        "version": "0.2.0",
        "day": "Day 2 – Alert Management & Risk Scoring",
        "uptime_seconds": round(uptime_seconds, 1),
    }


# ── Risk score info ───────────────────────────────────────────────────────────
@app.get("/risk-bands", tags=["Risk Scoring"], summary="Risk score band definitions")
def risk_bands() -> dict:
    """Return the risk score band definitions used by the scoring engine."""
    return {
        "description": "Risk scores are computed from severity + AbuseIPDB + VirusTotal signals.",
        "formula": "score = (severity_weight * 0.50) + (abuseipdb_score * 0.30) + (vt_score * 0.20)",
        "bands": [
            {"range": "0 – 25",   "category": "Low",      "color": "#28a745"},
            {"range": "26 – 50",  "category": "Medium",   "color": "#ffc107"},
            {"range": "51 – 75",  "category": "High",     "color": "#fd7e14"},
            {"range": "76 – 100", "category": "Critical", "color": "#dc3545"},
        ],
        "weights": {
            "severity":    "50%",
            "abuseipdb":   "30%",
            "virustotal":  "20%",
        },
    }
