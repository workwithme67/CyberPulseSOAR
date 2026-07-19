"""
Alert service layer – all database operations for the Alert entity.

Responsibilities
----------------
- Full CRUD (Create, Read, Update, Delete).
- Orchestrates TI enrichment on creation.
- Computes risk score on creation.
- Writes timeline events for every mutating operation.
- Dashboard aggregate queries.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus, SeverityLevel
from app.models.timeline import EventType
from app.models.schemas import AlertCreate, AlertStatusUpdate
from app.services import risk_scoring, threat_intelligence, timeline_service
from app.utils.helpers import get_logger

logger = get_logger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_alert_id() -> str:
    return f"ALERT-{uuid.uuid4().hex[:8].upper()}"


def _get_or_404(db: Session, alert_id: int) -> Alert:
    """Fetch an Alert by integer PK or raise 404."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return alert


# ── Create ────────────────────────────────────────────────────────────────────

def create_alert(db: Session, payload: AlertCreate) -> Alert:
    """
    Ingest a new alert.

    Pipeline:
      1. Validate & persist the core alert row.
      2. Timeline: AlertCreated.
      3. Run TI enrichment (real API or mock).
      4. Timeline: AlertEnriched.
      5. Compute risk score.
      6. Timeline: RiskCalculated.
      7. Update alert with TI result + risk score and commit.

    Returns
    -------
    Alert : Fully populated ORM instance.
    """
    # ── Step 1: Persist alert skeleton ────────────────────────────────────────
    alert = Alert(
        alert_id=_generate_alert_id(),
        alert_type=payload.alert_type,
        source_ip=payload.source_ip,
        severity=payload.severity,
        description=payload.description,
        status=payload.status,
        risk_score=0.0,
        threat_verdict="Pending",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # ── Step 2: Timeline — AlertCreated ───────────────────────────────────────
    timeline_service.add_event(
        db=db,
        alert_db_id=alert.id,
        alert_id=alert.alert_id,
        event_type=EventType.AlertCreated,
        description=(
            f"Alert ingested | type={alert.alert_type} "
            f"ip={alert.source_ip} severity={alert.severity}"
        ),
        metadata={"alert_type": alert.alert_type, "source_ip": alert.source_ip,
                  "severity": alert.severity},
    )

    # ── Step 3: Threat intelligence enrichment ────────────────────────────────
    ti_data: Dict[str, Any] = {}
    ti_score = 0.0
    threat_verdict = "Unknown"

    try:
        ti_data = threat_intelligence.enrich_ip(alert.source_ip)
        ti_score = ti_data.get("aggregate_confidence", 0.0) / 100.0
        threat_verdict = ti_data.get("threat_verdict", "Unknown")
    except Exception as exc:
        logger.warning("TI enrichment failed for %s: %s", alert.source_ip, exc)

    # ── Step 4: Timeline — AlertEnriched ─────────────────────────────────────
    timeline_service.add_event(
        db=db,
        alert_db_id=alert.id,
        alert_id=alert.alert_id,
        event_type=EventType.AlertEnriched,
        description=(
            f"TI enrichment complete | verdict={threat_verdict} "
            f"confidence={round(ti_score * 100, 1)}"
        ),
        metadata={
            "threat_verdict": threat_verdict,
            "aggregate_confidence": round(ti_score * 100, 2),
            "abuseipdb_score": ti_data.get("abuseipdb", {}).get("abuse_confidence_score", 0),
            "vt_malicious": ti_data.get("virustotal", {}).get("malicious_count", 0),
        },
    )

    # ── Step 5: Risk scoring ──────────────────────────────────────────────────
    computed_risk = risk_scoring.calculate_risk_score(
        severity=alert.severity,
        alert_type=alert.alert_type,
        ti_score=ti_score,
    )
    risk_level = risk_scoring.get_risk_level(computed_risk)

    # ── Step 6: Timeline — RiskCalculated ────────────────────────────────────
    timeline_service.add_event(
        db=db,
        alert_db_id=alert.id,
        alert_id=alert.alert_id,
        event_type=EventType.RiskCalculated,
        description=(
            f"Risk score computed | score={computed_risk} level={risk_level}"
        ),
        metadata={"risk_score": computed_risk, "risk_level": risk_level},
    )

    # ── Step 7: Update alert with enrichment & score ──────────────────────────
    alert.risk_score = computed_risk
    alert.threat_verdict = threat_verdict
    alert.enrichment_data = json.dumps(ti_data, default=str) if ti_data else None

    db.commit()
    db.refresh(alert)

    # ── Step 8: Playbook Automation (Rule-based execution) ────────────────────
    from app.config import settings
    if settings.PLAYBOOK_AUTO_TRIGGER:
        try:
            from app.services import playbook_service
            # Rule 1: Auto Block IP if malicious OR risk score >= 76 (Critical)
            if alert.threat_verdict == "Malicious" or alert.risk_score >= 76.0:
                logger.info("Auto-triggering block_ip playbook for alert %s", alert.alert_id)
                playbook_service.execute_playbook(
                    db=db,
                    alert_id=alert.alert_id,
                    playbook_name="block_ip",
                    executed_by="SOAR Automation",
                    notes=f"Automated block rule triggered: Verdict={alert.threat_verdict}, Risk={alert.risk_score}"
                )
            
            # Rule 2: Auto Isolate Host if Ransomware
            if "ransomware" in alert.alert_type.lower():
                logger.info("Auto-triggering isolate_host playbook for alert %s", alert.alert_id)
                playbook_service.execute_playbook(
                    db=db,
                    alert_id=alert.alert_id,
                    playbook_name="isolate_host",
                    executed_by="SOAR Automation",
                    notes="Automated host isolation triggered: Ransomware activity detected"
                )
                
            # Rule 3: Auto Escalate if Critical severity
            if alert.severity == SeverityLevel.Critical:
                logger.info("Auto-triggering escalate playbook for alert %s", alert.alert_id)
                playbook_service.execute_playbook(
                    db=db,
                    alert_id=alert.alert_id,
                    playbook_name="escalate",
                    executed_by="SOAR Automation",
                    notes="Automated SOC escalation triggered: Critical severity alert"
                )
        except Exception as auto_exc:
            logger.error("Error executing auto-containment playbook for alert %s: %s", alert.alert_id, auto_exc)

    logger.info(
        "Alert created | alert_id=%s type=%s ip=%s severity=%s "
        "risk=%.1f verdict=%s",
        alert.alert_id, alert.alert_type, alert.source_ip,
        alert.severity, alert.risk_score, alert.threat_verdict,
    )
    return alert



# ── Read (list) ───────────────────────────────────────────────────────────────

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
    alert_type: Optional[str] = None,
) -> List[Alert]:
    """Return a paginated, optionally filtered list of alerts."""
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


# ── Read (single) ─────────────────────────────────────────────────────────────

def get_alert_by_id(db: Session, alert_id: int) -> Alert:
    """Fetch by integer PK; raises 404 if not found."""
    return _get_or_404(db, alert_id)


# ── Update status ─────────────────────────────────────────────────────────────

def update_alert_status(
    db: Session,
    alert_id: int,
    payload: AlertStatusUpdate,
) -> Alert:
    """
    Transition the alert's workflow status and record a timeline event.

    Raises 404 if the alert does not exist.
    """
    alert = _get_or_404(db, alert_id)
    old_status = alert.status
    new_status = payload.status

    alert.status = new_status
    alert.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(alert)

    timeline_service.add_event(
        db=db,
        alert_db_id=alert.id,
        alert_id=alert.alert_id,
        event_type=EventType.StatusUpdated,
        description=f"Status changed: {old_status} -> {new_status}",
        metadata={"old_status": old_status, "new_status": new_status},
    )

    logger.info(
        "Alert status updated | alert_id=%s %s -> %s",
        alert.alert_id, old_status, new_status,
    )
    return alert


# ── Delete ────────────────────────────────────────────────────────────────────

def delete_alert(db: Session, alert_id: int) -> Dict[str, str]:
    """
    Permanently delete an alert and all its timeline events.

    The timeline CASCADE delete on the ORM model removes child events
    automatically.

    Returns
    -------
    dict : Confirmation with the deleted alert_id.

    Raises
    ------
    HTTPException 404 : Alert not found.
    """
    alert = _get_or_404(db, alert_id)
    alert_ref = alert.alert_id    # capture before deletion

    # Record final event before cascade deletes it along with the alert
    timeline_service.add_event(
        db=db,
        alert_db_id=alert.id,
        alert_id=alert.alert_id,
        event_type=EventType.AlertDeleted,
        description=f"Alert permanently deleted from the system.",
        metadata={"alert_type": alert.alert_type, "source_ip": alert.source_ip},
    )

    db.delete(alert)
    db.commit()

    logger.info("Alert deleted | alert_id=%s", alert_ref)
    return {"message": f"Alert {alert_ref} deleted successfully.", "alert_id": alert_ref}


# ── Count helpers ─────────────────────────────────────────────────────────────

def count_alerts(db: Session) -> int:
    return db.query(Alert).count()


def count_by_status(db: Session, alert_status: AlertStatus) -> int:
    return db.query(Alert).filter(Alert.status == alert_status).count()


def count_by_severity(db: Session, severity: SeverityLevel) -> int:
    return db.query(Alert).filter(Alert.severity == severity).count()


def count_by_verdict(db: Session, verdict: str) -> int:
    return db.query(Alert).filter(Alert.threat_verdict == verdict).count()


def avg_risk_score(db: Session) -> float:
    result = db.query(func.avg(Alert.risk_score)).scalar()
    return round(float(result or 0.0), 2)


def risk_distribution(db: Session) -> Dict[str, int]:
    """Return count of alerts in each risk band."""
    all_alerts = db.query(Alert.risk_score).all()
    buckets = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for (score,) in all_alerts:
        s = score or 0.0
        level = risk_scoring.get_risk_level(s)
        buckets[level] += 1
    return buckets


def get_recent_alerts(db: Session, limit: int = 10) -> List[Alert]:
    return (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
