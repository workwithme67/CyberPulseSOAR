"""
SOAR Incident Containment Engine – Main Application Entry Point
===============================================================
50% Milestone: Full backend with TI enrichment, risk scoring,
dashboard analytics, incident timeline, and comprehensive Swagger docs.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.db import Base, engine
from app.routes import alerts, dashboard, auth, playbooks
from app.utils.helpers import get_logger, setup_logging

# ── Logging must be configured before any module uses get_logger() ───────────
setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE,
    max_bytes=settings.LOG_MAX_BYTES,
    backup_count=settings.LOG_BACKUP_COUNT,
)

logger = get_logger("soar.main")


# ── Lifespan: DB init on startup ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all tables on startup; log shutdown."""
    # Import models so SQLAlchemy knows about them before create_all()
    from app.models import alert, timeline, user, blocked_ip, playbook  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info(
        "SOAR Engine v%s starting | env=%s db=%s",
        app.version, settings.APP_ENV, settings.DATABASE_URL,
    )
    logger.info(
        "TI APIs | AbuseIPDB=%s | VirusTotal=%s",
        "LIVE" if settings.abuseipdb_enabled else "mock",
        "LIVE" if settings.virustotal_enabled else "mock",
    )
    yield
    logger.info("SOAR Engine shutting down.")


# ── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title="SOAR Incident Containment Engine",
    description=(
        "## Security Orchestration, Automation, and Response Platform\n\n"
        "Production-ready backend for ingesting, enriching, scoring, and triaging "
        "security incidents. At the 50% milestone this system provides:\n\n"
        "### Features\n"
        "- **Alert Management** — full CRUD with input validation\n"
        "- **Threat Intelligence** — AbuseIPDB + VirusTotal (live API or mock)\n"
        "- **Risk Scoring Engine** — weighted 0-100 score mapped to Low/Medium/High/Critical\n"
        "- **Incident Timeline** — chronological audit trail per alert\n"
        "- **Dashboard Analytics** — summary counts, risk histogram, recent alerts\n\n"
        "### Risk Score Bands\n"
        "| Score | Level    |\n"
        "|-------|----------|\n"
        "| 0-25  | 🟢 Low   |\n"
        "| 26-50 | 🟡 Medium|\n"
        "| 51-75 | 🟠 High  |\n"
        "|76-100 | 🔴 Critical|\n\n"
        "### Alert Workflow\n"
        "`Open` → `Investigating` → `Resolved`\n\n"
        "### Interactive Docs\n"
        "This page — explore and test every endpoint below."
    ),
    version="0.5.0",
    contact={"name": "Infotact Internship", "email": "intern@infotact.example"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "Health",
            "description": "Application health-check endpoints.",
        },
        {
            "name": "Alerts",
            "description": (
                "Full CRUD for security alerts. Includes automatic TI enrichment, "
                "risk scoring, and timeline tracking."
            ),
        },
        {
            "name": "Dashboard",
            "description": (
                "Aggregate analytics — counts, risk distribution, and recent activity."
            ),
        },
    ],
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(alerts.router,    prefix="/alerts",    tags=["Alerts"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(auth.router,      prefix="/auth",      tags=["Auth"])
app.include_router(playbooks.router, prefix="/playbooks", tags=["Playbooks"])


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"], summary="Health check")
@app.get("/", tags=["Health"], summary="Health check")
def health_check() -> dict:
    """Root/Health health-check — returns running status and version."""
    return {
        "status":  "running",
        "version": "0.5.0",
        "project": "SOAR Incident Containment Engine",
        "milestone": "50%",
        "docs":    "/docs",
        "ti_mode": {
            "abuseipdb":  "live" if settings.abuseipdb_enabled else "mock",
            "virustotal": "live" if settings.virustotal_enabled else "mock",
        },
    }


@app.get("/health/ti-diagnostics", tags=["Health"], summary="TI integration diagnostics")
def ti_diagnostics() -> dict:
    """Returns detailed diagnostics of threat intelligence integrations."""
    return {
        "abuseipdb": {
            "status": "live" if settings.abuseipdb_enabled else "mock",
            "api_key_configured": bool(settings.ABUSEIPDB_API_KEY),
            "api_key_valid_format": len(settings.ABUSEIPDB_API_KEY) > 10 if settings.ABUSEIPDB_API_KEY else False,
        },
        "virustotal": {
            "status": "live" if settings.virustotal_enabled else "mock",
            "api_key_configured": bool(settings.VIRUSTOTAL_API_KEY),
            "api_key_valid_format": len(settings.VIRUSTOTAL_API_KEY) > 10 if settings.VIRUSTOTAL_API_KEY else False,
        },
        "ipinfo": {
            "status": "live" if settings.ipinfo_enabled else "mock",
            "api_key_configured": bool(settings.IPINFO_API_KEY),
        },
        "playbook_auto_trigger": settings.PLAYBOOK_AUTO_TRIGGER,
    }

