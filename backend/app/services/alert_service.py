"""
Alert service layer – Day 2 enhanced CRUD + enrichment pipeline.

Changes from Day 1
------------------
- create_alert now runs threat intel enrichment and risk scoring automatically.
- Added update_alert_status() for PATCH /alerts/{id}/status.
- Added get_alerts_by_type() and get_alerts_by_ip() for future use.
- Imports threat_intelligence and risk_scoring services.
"""

from datetime import datetime, timezone
from typing import List, Optional
import logging

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.alert import Alert, SeverityLevel, AlertStatus
from app.models.schemas import AlertCreate, AlertStatusUpdate
from app.services.threat_intelligence import enrich_ip
from app.services.risk_scoring import score_alert

logger = logging.getLogger("soar.alert_service")


# ── Create ────────────────────────────────────────────────────────────────────

def create_alert(db: Session, payload: AlertCreate) -> Alert:
    """
    Persist a new alert with automatic threat intelligence enrichment
    and risk score computation.

    Pipeline
    --------
    1. Validate payload (handled by Pydantic before this is called).
    2. Enrich source_ip via mock TI services.
    3. Calculate risk score from severity + TI signals.
    4. Persist alert to the database.
    5. Return the created ORM instance.
    """
    logger.info("Ingesting alert: type=%s ip=%s severity=%s",
                payload.alert_type, payload.source_ip, payload.severity)

    # Step 2 – Threat intelligence enrichment
    enrichment = enrich_ip(payload.source_ip)

    # Step 3 – Risk scoring
    scoring = score_alert(severity=payload.severity, enrichment=enrichment)
    risk_score = scoring["score"]

    logger.info("Risk score for %s: %.2f (%s)", payload.source_ip, risk_score, scoring["category"])

    # Step 4 – Persist
    alert = Alert(
        alert_type=payload.alert_type,
        source_ip=payload.source_ip,
        severity=payload.severity,
        description=payload.description,
        status=payload.status,
        risk_score=risk_score,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    logger.info("Alert id=%d created successfully.", alert.id)
    return alert


# ── Read – list ───────────────────────────────────────────────────────────────

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
    alert_type: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> List[Alert]:
    """
    Retrieve a paginated, optionally filtered list of alerts.

    New filters in Day 2: alert_type (partial match) and source_ip (exact match).
    """
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


# ── Read – single ─────────────────────────────────────────────────────────────

def get_alert_by_id(db: Session, alert_id: int) -> Alert:
    """
    Fetch a single alert by primary key. Raises HTTP 404 if not found.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return alert


# ── Update – status ───────────────────────────────────────────────────────────

def update_alert_status(
    db: Session, alert_id: int, payload: AlertStatusUpdate
) -> Alert:
    """
    Update the workflow status of an existing alert.

    - Validates the alert exists (raises 404 otherwise).
    - Prevents redundant updates (raises 400 if new status == current status).
    - Appends the analyst note to the description field if provided.
    - Updates the updated_at timestamp.

    Parameters
    ----------
    db       : SQLAlchemy session.
    alert_id : ID of the alert to update.
    payload  : AlertStatusUpdate schema containing new status and optional note.
    """
    alert = get_alert_by_id(db=db, alert_id=alert_id)

    if alert.status == payload.status:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Alert id={alert_id} is already in status '{payload.status}'.",
        )

    old_status = alert.status
    alert.status = payload.status
    alert.updated_at = datetime.now(timezone.utc)

    # Append analyst note to description if provided
    if payload.note:
        note_entry = f"\n[{alert.updated_at.strftime('%Y-%m-%d %H:%M')} UTC] Analyst note: {payload.note}"
        alert.description = (alert.description or "") + note_entry

    db.commit()
    db.refresh(alert)

    logger.info("Alert id=%d status updated: %s → %s", alert_id, old_status, payload.status)
    return alert


# ── Count – helper ────────────────────────────────────────────────────────────

def count_alerts(
    db: Session,
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
) -> int:
    """Return the total number of alerts matching optional filters."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    return query.count()


# ── Enriched single-alert fetch ───────────────────────────────────────────────

def get_enriched_alert(db: Session, alert_id: int) -> dict:
    """
    Fetch an alert and run a fresh (mock) threat intel lookup.

    Returns a dict containing the Alert ORM object plus TI summary data.
    Used by GET /alerts/{id}/enriched (Day 3 endpoint preview).
    """
    alert = get_alert_by_id(db=db, alert_id=alert_id)
    enrichment = enrich_ip(alert.source_ip)
    scoring = score_alert(severity=alert.severity, enrichment=enrichment)
    return {
        "alert": alert,
        "enrichment": enrichment,
        "scoring": scoring,
    }
