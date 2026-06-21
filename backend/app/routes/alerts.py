"""
Alert router – HTTP layer for alert management endpoints. Day 2 Enhanced.

Endpoints
---------
POST   /alerts/                     Ingest a new security alert.
GET    /alerts/                     List alerts with filters & pagination.
GET    /alerts/{alert_id}           Retrieve a single alert by ID.
PATCH  /alerts/{alert_id}/status    Update the workflow status of an alert.
GET    /alerts/{alert_id}/enriched  Fetch alert with live threat intel (preview).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, status, Path
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.alert import SeverityLevel, AlertStatus
from app.models.schemas import (
    AlertCreate,
    AlertResponse,
    AlertEnrichedResponse,
    AlertListResponse,
    AlertStatusUpdate,
    ThreatIntelSummary,
)
from app.services import alert_service

logger = logging.getLogger("soar.routes.alerts")
router = APIRouter()


# ── POST /alerts/ ─────────────────────────────────────────────────────────────
@router.post(
    "/",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new security alert",
    description=(
        "Submit a raw security alert for ingestion. "
        "The engine will automatically:\n\n"
        "1. **Validate** the source IP (must be a valid IPv4 address).\n"
        "2. **Enrich** the IP via mock AbuseIPDB and VirusTotal lookups.\n"
        "3. **Score** the alert with a 0-100 risk score.\n"
        "4. **Persist** the alert and return the created record."
    ),
)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Create and enrich a new security alert."""
    return alert_service.create_alert(db=db, payload=payload)


# ── GET /alerts/ ──────────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List security alerts",
    description=(
        "Retrieve a paginated list of security alerts. "
        "Supports filtering by **severity**, **status**, **alert_type** (partial), "
        "and **source_ip** (exact). Results are ordered by most recent first."
    ),
)
def list_alerts(
    skip: int = Query(default=0, ge=0, description="Records to skip (offset)"),
    limit: int = Query(default=50, ge=1, le=100, description="Max records to return"),
    severity: Optional[SeverityLevel] = Query(
        default=None, description="Filter by severity: LOW | MEDIUM | HIGH | CRITICAL"
    ),
    alert_status: Optional[AlertStatus] = Query(
        default=None, alias="status",
        description="Filter by status: OPEN | INVESTIGATING | RESOLVED | DISMISSED"
    ),
    alert_type: Optional[str] = Query(
        default=None, description="Partial match on alert type (e.g. 'Brute')"
    ),
    source_ip: Optional[str] = Query(
        default=None, description="Exact match on source IP address"
    ),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """Return a paginated, filtered list of alerts."""
    alerts = alert_service.get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=alert_status,
        alert_type=alert_type,
        source_ip=source_ip,
    )
    total = alert_service.count_alerts(
        db=db, severity=severity, status=alert_status
    )
    return AlertListResponse(total=total, page_size=len(alerts), alerts=alerts)


# ── GET /alerts/{alert_id} ────────────────────────────────────────────────────
@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
    description="Retrieve the full details of a specific alert by its numeric ID.",
)
def get_alert(
    alert_id: int = Path(..., ge=1, description="Unique alert ID"),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Fetch a single alert by its primary key."""
    return alert_service.get_alert_by_id(db=db, alert_id=alert_id)


# ── PATCH /alerts/{alert_id}/status ──────────────────────────────────────────
@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update alert workflow status",
    description=(
        "Transition an alert to a new workflow status.\n\n"
        "**Allowed status values:**\n"
        "- `OPEN` – Initial state, alert has not been reviewed.\n"
        "- `INVESTIGATING` – An analyst is actively working on this alert.\n"
        "- `RESOLVED` – The alert has been investigated and closed.\n"
        "- `DISMISSED` – The alert was determined to be a false positive.\n\n"
        "An optional **analyst note** can be included and will be appended "
        "to the alert description with a timestamp."
    ),
)
def update_alert_status(
    alert_id: int = Path(..., ge=1, description="Unique alert ID"),
    payload: AlertStatusUpdate = ...,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """
    Update the workflow status of an alert.

    Returns the updated alert object.
    Raises **404** if the alert does not exist.
    Raises **400** if the alert is already in the requested status.
    """
    return alert_service.update_alert_status(
        db=db, alert_id=alert_id, payload=payload
    )


# ── GET /alerts/{alert_id}/enriched ──────────────────────────────────────────
@router.get(
    "/{alert_id}/enriched",
    response_model=AlertEnrichedResponse,
    summary="Get alert with threat intelligence context",
    description=(
        "Fetch a single alert and run a **live** (mock) threat intelligence "
        "lookup on its source IP. Returns the full alert plus AbuseIPDB and "
        "VirusTotal data and a fresh risk score calculation."
    ),
)
def get_enriched_alert(
    alert_id: int = Path(..., ge=1, description="Unique alert ID"),
    db: Session = Depends(get_db),
) -> AlertEnrichedResponse:
    """Fetch alert with live threat intelligence enrichment."""
    result = alert_service.get_enriched_alert(db=db, alert_id=alert_id)
    alert = result["alert"]
    enrichment = result["enrichment"]

    threat_intel = ThreatIntelSummary(
        ip=enrichment["ip"],
        abuseipdb_score=enrichment["abuseipdb_score"],
        abuseipdb_reports=enrichment["abuseipdb_reports"],
        virustotal_malicious=enrichment["virustotal_malicious"],
        virustotal_suspicious=enrichment["virustotal_suspicious"],
        is_known_malicious=enrichment["is_known_malicious"],
    )

    return AlertEnrichedResponse(
        id=alert.id,
        alert_type=alert.alert_type,
        source_ip=alert.source_ip,
        severity=alert.severity,
        description=alert.description,
        status=alert.status,
        risk_score=result["scoring"]["score"],
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        threat_intel=threat_intel,
    )
