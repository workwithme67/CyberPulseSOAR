"""
Alert router – HTTP layer for all /alerts endpoints.

Endpoints
---------
POST   /alerts/                    Ingest a new security alert.
GET    /alerts/                    List alerts (filters + pagination).
GET    /alerts/{alert_id}          Get a single alert by integer ID.
PATCH  /alerts/{alert_id}/status   Update workflow status.
DELETE /alerts/{alert_id}          Permanently delete an alert.
GET    /alerts/{alert_id}/enrich   Get TI enrichment for the alert's IP.
GET    /alerts/{alert_id}/timeline Get the full lifecycle event timeline.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.alert import AlertStatus, SeverityLevel
from app.models.user import User
from app.models.schemas import (
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdate,
    AlertTimeline,
    TimelineEventResponse,
)
from app.routes.deps import require_admin, require_analyst, require_any_role
from app.services import alert_service, threat_intelligence, timeline_service
from app.services.risk_scoring import score_summary
from app.utils.helpers import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ── POST /alerts ──────────────────────────────────────────────────────────────
@router.post(
    "/",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new security alert",
    description=(
        "Creates and persists a new security alert.\n\n"
        "**Automatic pipeline:**\n"
        "1. Validate source IPv4 and severity.\n"
        "2. Run AbuseIPDB + VirusTotal threat intelligence.\n"
        "3. Compute risk score (0-100).\n"
        "4. Record a full lifecycle timeline.\n\n"
        "**Severity:** `Low` | `Medium` | `High` | `Critical` (case-insensitive)\n\n"
        "**Status:** `Open` | `Investigating` | `Resolved` (case-insensitive)"
    ),
)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> AlertResponse:
    """Ingest and persist a new security alert with automatic enrichment."""
    return alert_service.create_alert(db=db, payload=payload)


# ── GET /alerts ───────────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List security alerts",
    description="Paginated alert list. Supports filtering by severity, status, and alert_type.",
)
def list_alerts(
    skip: int = Query(default=0, ge=0, description="Records to skip (offset)"),
    limit: int = Query(default=50, ge=1, le=100, description="Max records to return"),
    severity: Optional[SeverityLevel] = Query(
        default=None, description="Filter by severity (Low | Medium | High | Critical)"
    ),
    alert_status: Optional[AlertStatus] = Query(
        default=None, alias="status",
        description="Filter by status (Open | Investigating | Resolved)",
    ),
    alert_type: Optional[str] = Query(
        default=None, description="Filter by alert type substring (case-insensitive)"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role),
) -> AlertListResponse:
    """Return a paginated list of security alerts with optional filters."""
    alerts = alert_service.get_alerts(
        db=db, skip=skip, limit=limit,
        severity=severity, status=alert_status, alert_type=alert_type,
    )
    total = alert_service.count_alerts(db=db)
    return AlertListResponse(total=total, alerts=alerts)


# ── GET /alerts/{alert_id} ────────────────────────────────────────────────────
@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
    description="Retrieve a specific security alert by its integer primary key.",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role),
) -> AlertResponse:
    """Retrieve a specific security alert by its numeric ID."""
    return alert_service.get_alert_by_id(db=db, alert_id=alert_id)


# ── PATCH /alerts/{alert_id}/status ──────────────────────────────────────────
@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update alert workflow status",
    description=(
        "Transition the alert status and record a timeline event.\n\n"
        "**Allowed values:** `Open` | `Investigating` | `Resolved` (case-insensitive)"
    ),
)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> AlertResponse:
    """Transition the alert's workflow status."""
    return alert_service.update_alert_status(db=db, alert_id=alert_id, payload=payload)


# ── DELETE /alerts/{alert_id} ─────────────────────────────────────────────────
@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete an alert",
    description=(
        "Permanently remove an alert and all its timeline events from the database.\n\n"
        "> **Warning:** This action is irreversible."
    ),
)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Dict[str, str]:
    """Permanently delete an alert and all associated timeline events."""
    return alert_service.delete_alert(db=db, alert_id=alert_id)


# ── GET /alerts/{alert_id}/enrich ────────────────────────────────────────────
@router.get(
    "/{alert_id}/enrich",
    summary="Threat intelligence enrichment for an alert",
    description=(
        "Returns live AbuseIPDB + VirusTotal threat intelligence data "
        "for the source IP of the specified alert, plus risk score details."
    ),
)
def enrich_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role),
) -> Dict[str, Any]:
    """Return TI enrichment and risk score summary for an alert."""
    alert    = alert_service.get_alert_by_id(db=db, alert_id=alert_id)
    ti_data  = threat_intelligence.enrich_ip(alert.source_ip)
    risk_info = score_summary(alert.risk_score)

    return {
        "alert_id":            alert.alert_id,
        "source_ip":           alert.source_ip,
        "risk_info":           risk_info,
        "threat_intelligence": ti_data,
    }


# ── GET /alerts/{alert_id}/timeline ──────────────────────────────────────────
@router.get(
    "/{alert_id}/timeline",
    response_model=AlertTimeline,
    summary="Get the lifecycle timeline for an alert",
    description=(
        "Returns the full chronological event timeline for an alert:\n\n"
        "- `AlertCreated` – alert was ingested.\n"
        "- `AlertEnriched` – TI lookup completed.\n"
        "- `RiskCalculated` – risk score computed.\n"
        "- `StatusUpdated` – workflow status changed.\n"
        "- `AlertDeleted` – alert was removed."
    ),
)
def get_alert_timeline(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role),
) -> AlertTimeline:
    """Retrieve the full incident lifecycle timeline for an alert."""
    alert = alert_service.get_alert_by_id(db=db, alert_id=alert_id)
    events = timeline_service.get_timeline(db=db, alert_db_id=alert.id)

    return AlertTimeline(
        alert_id=alert.alert_id,
        alert_type=alert.alert_type,
        source_ip=alert.source_ip,
        severity=alert.severity,
        status=alert.status,
        risk_score=alert.risk_score,
        threat_verdict=alert.threat_verdict,
        created_at=alert.created_at,
        events=[TimelineEventResponse.model_validate(e) for e in events],
    )
