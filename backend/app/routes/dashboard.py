"""
Dashboard router – analytics and summary endpoints.

Endpoints
---------
GET /dashboard/summary           Overall system health counts.
GET /dashboard/risk-distribution Risk score histogram (Low/Medium/High/Critical).
GET /dashboard/recent-alerts     Most recent N alerts (default 10).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.alert import AlertStatus, SeverityLevel
from app.models.schemas import (
    DashboardSummary,
    RecentAlertsResponse,
    RiskBucket,
    RiskDistributionResponse,
)
from app.services import alert_service, playbook_service
from app.utils.helpers import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ── GET /dashboard/summary ────────────────────────────────────────────────────
@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Dashboard summary",
    description=(
        "Returns real-time aggregate counts of alerts broken down by:\n\n"
        "- **Workflow status** — Open, Investigating, Resolved.\n"
        "- **Severity** — Low, Medium, High, Critical.\n"
        "- **Threat verdict** — Malicious, Suspicious IPs.\n"
        "- **Average risk score** across all alerts."
    ),
)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    """Return live aggregate dashboard metrics."""
    total          = alert_service.count_alerts(db)
    open_count     = alert_service.count_by_status(db, AlertStatus.Open)
    invest_count   = alert_service.count_by_status(db, AlertStatus.Investigating)
    resolved_count = alert_service.count_by_status(db, AlertStatus.Resolved)
    critical_count = alert_service.count_by_severity(db, SeverityLevel.Critical)
    high_count     = alert_service.count_by_severity(db, SeverityLevel.High)
    medium_count   = alert_service.count_by_severity(db, SeverityLevel.Medium)
    low_count      = alert_service.count_by_severity(db, SeverityLevel.Low)
    malicious_count  = alert_service.count_by_verdict(db, "Malicious")
    suspicious_count = alert_service.count_by_verdict(db, "Suspicious")
    avg_score      = alert_service.avg_risk_score(db)
    blocked_ips_count = playbook_service.count_blocked_ips(db)

    logger.info(
        "Dashboard summary | total=%d open=%d critical=%d avg_risk=%.1f",
        total, open_count, critical_count, avg_score,
    )

    return DashboardSummary(
        total_alerts=total,
        open_alerts=open_count,
        investigating_alerts=invest_count,
        resolved_alerts=resolved_count,
        critical_alerts=critical_count,
        high_alerts=high_count,
        medium_alerts=medium_count,
        low_alerts=low_count,
        malicious_ips=malicious_count,
        suspicious_ips=suspicious_count,
        avg_risk_score=avg_score,
        blocked_ips=blocked_ips_count,
    )


# ── GET /dashboard/risk-distribution ─────────────────────────────────────────
@router.get(
    "/risk-distribution",
    response_model=RiskDistributionResponse,
    summary="Risk score distribution",
    description=(
        "Returns a histogram of alerts grouped into the four risk bands:\n\n"
        "| Band     | Score Range |\n"
        "|----------|-------------|\n"
        "| Low      | 0 – 25      |\n"
        "| Medium   | 26 – 50     |\n"
        "| High     | 51 – 75     |\n"
        "| Critical | 76 – 100    |"
    ),
)
def risk_distribution(db: Session = Depends(get_db)) -> RiskDistributionResponse:
    """Return the risk score histogram across all alerts."""
    dist  = alert_service.risk_distribution(db)
    total = alert_service.count_alerts(db)

    band_meta = {
        "Low":      "0-25",
        "Medium":   "26-50",
        "High":     "51-75",
        "Critical": "76-100",
    }

    buckets = [
        RiskBucket(
            label=label,
            range=band_meta[label],
            count=count,
            pct=round((count / total * 100) if total > 0 else 0.0, 1),
        )
        for label, count in dist.items()
    ]

    return RiskDistributionResponse(total=total, buckets=buckets)


# ── GET /dashboard/recent-alerts ──────────────────────────────────────────────
@router.get(
    "/recent-alerts",
    response_model=RecentAlertsResponse,
    summary="Most recent alerts",
    description="Returns the most recently created alerts (default 10, max 50).",
)
def recent_alerts(
    limit: int = Query(default=10, ge=1, le=50, description="Number of recent alerts to return"),
    db: Session = Depends(get_db),
) -> RecentAlertsResponse:
    """Return the N most recently created alerts."""
    alerts = alert_service.get_recent_alerts(db=db, limit=limit)
    return RecentAlertsResponse(count=len(alerts), alerts=alerts)
