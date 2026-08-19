"""
Updated Pydantic schemas for request validation and response serialisation.

Schema Map
----------
  AlertBase              – shared fields.
  AlertCreate            – POST /alerts  request body.
  AlertUpdate            – PATCH /alerts/{id}  request body.
  AlertStatusUpdate      – PATCH /alerts/{id}/status  request body.
  AlertResponse          – Full alert object returned to the client.
  AlertListResponse      – Paginated list wrapper.

  TimelineEventResponse  – Single timeline event.
  AlertTimeline          – Alert + its full event list.

  DashboardSummary       – GET /dashboard/summary.
  RiskDistribution       – GET /dashboard/risk-distribution.
  RecentAlertsResponse   – GET /dashboard/recent-alerts.
  AlertTrendPoint        – One point in an alert trend series.
  CountryCount           – One country in geographic distribution.

  UserCreate             – POST /auth/register  request body.
  UserLogin              – POST /auth/login  request body.
  UserResponse           – User record returned to the client.
  TokenResponse          – JWT token response.

  PlaybookExecuteRequest – POST /playbooks/execute  request body.
  PlaybookExecutionResponse – Single playbook execution record.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.alert import AlertStatus, SeverityLevel
from app.models.user import UserRole


# ── IP Validators ─────────────────────────────────────────────────────────────
def _validate_ipv4(v: str) -> str:
    """Accept only valid IPv4 addresses."""
    v = v.strip()
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(
            f"'{v}' is not a valid IP address. "
            "Provide a valid IPv4 address (e.g. 192.168.1.1)."
        )
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(
            f"'{v}' is an IPv6 address. Only IPv4 addresses are accepted."
        )
    return v


def _normalise_severity(v: str) -> str:
    allowed = [e.value for e in SeverityLevel]
    if isinstance(v, str):
        for a in allowed:
            if a.lower() == v.strip().lower():
                return a
    if v in allowed:
        return v
    raise ValueError(f"'{v}' is not a valid severity. Allowed: {allowed}.")


def _normalise_status(v: str) -> str:
    allowed = [e.value for e in AlertStatus]
    if isinstance(v, str):
        for a in allowed:
            if a.lower() == v.strip().lower():
                return a
    if v in allowed:
        return v
    raise ValueError(f"'{v}' is not a valid status. Allowed: {allowed}.")


# ─────────────────────────────────────────────────────────────────────────────
# Alert Schemas
# ─────────────────────────────────────────────────────────────────────────────

class AlertBase(BaseModel):
    alert_type: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Category of the security alert",
        examples=["Brute Force", "Port Scan", "Malware Detection"],
    )
    source_ip: str = Field(
        ...,
        description="Valid IPv4 address that triggered the alert",
        examples=["192.168.1.100", "203.0.113.42"],
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.Medium,
        description="Alert severity: Low | Medium | High | Critical",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable context",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        return _validate_ipv4(v)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        return _normalise_severity(v)


class AlertCreate(AlertBase):
    """Schema for POST /alerts."""
    status: AlertStatus = Field(
        default=AlertStatus.Open,
        description="Initial status (Open | Investigating | Resolved)",
    )

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, v: str) -> str:
        return _normalise_status(v)


class AlertUpdate(BaseModel):
    """Schema for PATCH /alerts/{id} – update any subset of fields."""
    alert_type:  Optional[str]          = Field(None, min_length=2, max_length=100)
    severity:    Optional[SeverityLevel] = None
    status:      Optional[AlertStatus]   = None
    description: Optional[str]           = Field(None, max_length=500)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v
        return _normalise_severity(v)

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, v):
        if v is None:
            return v
        return _normalise_status(v)


class AlertStatusUpdate(BaseModel):
    """Schema for PATCH /alerts/{id}/status."""
    status: AlertStatus = Field(
        ...,
        description="New workflow status (Open | Investigating | Resolved)",
    )

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, v: str) -> str:
        return _normalise_status(v)


class AlertResponse(AlertBase):
    """Full alert record returned to the client."""
    id:              int
    alert_id:        str
    status:          AlertStatus
    risk_score:      float
    threat_verdict:  Optional[str]
    enrichment_data: Optional[str] = None
    
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None
    country:         Optional[str] = None
    city:            Optional[str] = None
    
    sla_status:      Optional[str] = None
    
    created_at:      datetime
    updated_at:      datetime

    model_config = {"from_attributes": True}


class RelatedAlertResponse(BaseModel):
    """Summarized alert record for related incidents."""
    id:          int
    alert_id:    str
    alert_type:  str
    source_ip:   str
    severity:    str
    status:      str
    created_at:  datetime
    
    model_config = {"from_attributes": True}

class RelatedAlertsResponse(BaseModel):
    """List of related alerts."""
    count:  int
    alerts: List[RelatedAlertResponse]


class AlertListResponse(BaseModel):
    """Paginated alert list."""
    total:  int = Field(..., description="Total matching alerts in the database")
    alerts: List[AlertResponse]


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Schemas
# ─────────────────────────────────────────────────────────────────────────────

class TimelineEventResponse(BaseModel):
    """A single event in an alert's lifecycle."""
    id:            int
    alert_id:      str
    event_type:    str
    description:   str
    metadata_json: Optional[str] = None
    occurred_at:   datetime

    model_config = {"from_attributes": True}


class AlertTimeline(BaseModel):
    """Alert enriched with its full event timeline."""
    alert_id:       str
    alert_type:     str
    source_ip:      str
    severity:       str
    status:         str
    risk_score:     float
    threat_verdict: Optional[str]
    created_at:     datetime
    events:         List[TimelineEventResponse]


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Schemas
# ─────────────────────────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    """Summary counts returned by GET /dashboard/summary."""
    total_alerts:         int
    open_alerts:          int
    investigating_alerts: int
    resolved_alerts:      int
    critical_alerts:      int
    high_alerts:          int
    medium_alerts:        int
    low_alerts:           int
    malicious_ips:        int
    suspicious_ips:       int
    avg_risk_score:       float
    blocked_ips:          int


class RiskBucket(BaseModel):
    """One bucket in the risk distribution histogram."""
    label: str    # "Low", "Medium", "High", "Critical"
    range: str    # "0-25", "26-50", "51-75", "76-100"
    count: int
    pct:   float  # Percentage of total


class RiskDistributionResponse(BaseModel):
    """Risk score histogram returned by GET /dashboard/risk-distribution."""
    total:   int
    buckets: List[RiskBucket]


class RecentAlertsResponse(BaseModel):
    """Most recent N alerts returned by GET /dashboard/recent-alerts."""
    count:  int
    alerts: List[AlertResponse]


class AlertTrendPoint(BaseModel):
    """One day in the alert trend series."""
    date:  str   # ISO date string "2024-06-01"
    count: int


class AlertTrendResponse(BaseModel):
    """Alert creation trend over last N days."""
    days:   int
    points: List[AlertTrendPoint]


class CountryCount(BaseModel):
    """Alert count by country."""
    country: str
    count:   int


class CountryDistributionResponse(BaseModel):
    """Geographic distribution of alerts."""
    total:     int
    countries: List[CountryCount]


# ─────────────────────────────────────────────────────────────────────────────
# Auth / User Schemas
# ─────────────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """Schema for POST /auth/register."""
    username:  str = Field(..., min_length=3, max_length=80)
    email:     EmailStr
    full_name: Optional[str] = Field(None, max_length=150)
    password:  str = Field(..., min_length=8, description="Minimum 8 characters")
    role:      UserRole = Field(default=UserRole.Viewer)


class UserLogin(BaseModel):
    """Schema for POST /auth/login."""
    username: str
    password: str


class UserResponse(BaseModel):
    """User record returned to the client (never exposes password)."""
    id:         int
    username:   str
    email:      str
    full_name:  Optional[str]
    role:       str
    is_active:  bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int    # seconds
    user:         UserResponse


# ─────────────────────────────────────────────────────────────────────────────
# Playbook Schemas
# ─────────────────────────────────────────────────────────────────────────────

class PlaybookExecuteRequest(BaseModel):
    """Request body for POST /playbooks/execute."""
    alert_id:      str = Field(..., description="Human-readable alert ID, e.g. ALERT-A3F80001")
    playbook_name: str = Field(
        ...,
        description="Name of playbook to execute",
        examples=["block_ip", "isolate_host", "notify_soc", "escalate"],
    )
    target:        Optional[str] = Field(
        None,
        description="Override target (IP, hostname). Defaults to alert source_ip.",
    )
    notes:         Optional[str] = Field(None, max_length=500)


class PlaybookExecutionResponse(BaseModel):
    """Single playbook execution record."""
    id:             int
    alert_id:       str
    playbook_name:  str
    action:         str
    target:         Optional[str]
    status:         str
    result_message: Optional[str]
    executed_by:    Optional[str]
    executed_at:    datetime

    model_config = {"from_attributes": True}


class PlaybookListResponse(BaseModel):
    """List of available playbooks."""
    playbooks: List[Dict[str, Any]]


class BlockedIPResponse(BaseModel):
    """Single blocked IP record."""
    id:         int
    ip_address: str
    alert_id:   Optional[str]
    reason:     Optional[str]
    blocked_by: Optional[str]
    blocked_at: datetime

    model_config = {"from_attributes": True}
