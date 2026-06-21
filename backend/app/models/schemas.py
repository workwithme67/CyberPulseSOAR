"""
Pydantic schemas for request validation and response serialisation – Day 2.

Schema hierarchy
----------------
AlertBase           – shared validated fields (alert_type, source_ip, severity).
AlertCreate         – POST /alerts request body.
AlertStatusUpdate   – PATCH /alerts/{id}/status request body.
AlertResponse       – Standard alert response (no enrichment).
AlertEnrichedResponse – Full response with risk score + threat intel summary.
AlertListResponse   – Paginated list wrapper.
"""

from datetime import datetime
from typing import Optional, List
import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.alert import SeverityLevel, AlertStatus, RiskCategory


# ── Helpers ──────────────────────────────────────────────────────────────────

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_valid_ipv4(value: str) -> bool:
    """Return True only for valid unicast IPv4 addresses."""
    try:
        addr = ipaddress.IPv4Address(value)
        return not addr.is_unspecified and not addr.is_reserved
    except ipaddress.AddressValueError:
        return False


# ── Base schema ──────────────────────────────────────────────────────────────

class AlertBase(BaseModel):
    alert_type: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Category/type of the security alert",
        examples=["Brute Force Attack", "Port Scan", "SQL Injection", "Malware Detection"],
    )
    source_ip: str = Field(
        ...,
        description="IPv4 address of the source that triggered the alert",
        examples=["203.0.113.42", "198.51.100.17"],
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.MEDIUM,
        description="Severity level: LOW | MEDIUM | HIGH | CRITICAL",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable context about the alert",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        """
        Strict IPv4 validation.
        - Must be a valid IPv4 address.
        - Must not be an unspecified (0.0.0.0) or reserved address.
        """
        if not _is_valid_ipv4(v):
            raise ValueError(
                f"'{v}' is not a valid IPv4 address. "
                "Provide a valid unicast IPv4 address (e.g. 203.0.113.42)."
            )
        return v

    @field_validator("alert_type")
    @classmethod
    def sanitize_alert_type(cls, v: str) -> str:
        """Strip extra whitespace and title-case the alert type."""
        return " ".join(v.strip().split())


# ── Create schema ─────────────────────────────────────────────────────────────

class AlertCreate(AlertBase):
    """
    Request body for POST /alerts.

    All fields from AlertBase are required/optional as defined there.
    The `status` defaults to OPEN; `risk_score` is computed server-side.
    """
    status: AlertStatus = Field(
        default=AlertStatus.OPEN,
        description="Initial workflow status (defaults to OPEN)",
    )


# ── Status-update schema ──────────────────────────────────────────────────────

class AlertStatusUpdate(BaseModel):
    """
    Request body for PATCH /alerts/{id}/status.

    Allowed transitions: OPEN → INVESTIGATING → RESOLVED | DISMISSED.
    """
    status: AlertStatus = Field(
        ...,
        description="New workflow status: OPEN | INVESTIGATING | RESOLVED | DISMISSED",
    )
    note: Optional[str] = Field(
        default=None,
        max_length=300,
        description="Optional analyst note explaining the status change",
    )


# ── Threat Intel summary (embedded in enriched response) ─────────────────────

class ThreatIntelSummary(BaseModel):
    """Aggregated mock threat intelligence data for an IP."""
    ip: str
    abuseipdb_score: int = Field(description="AbuseIPDB confidence score (0-100)")
    abuseipdb_reports: int = Field(description="Number of abuse reports")
    virustotal_malicious: int = Field(description="VT malicious engine votes")
    virustotal_suspicious: int = Field(description="VT suspicious engine votes")
    is_known_malicious: bool = Field(description="True if IP is flagged by either source")


# ── Response schemas ──────────────────────────────────────────────────────────

class AlertResponse(AlertBase):
    """Standard alert response returned by most endpoints."""

    id: int = Field(description="Unique alert identifier")
    status: AlertStatus
    risk_score: float = Field(description="Computed risk score (0-100)")
    risk_category: Optional[str] = Field(
        default=None, description="Risk category label: Low | Medium | High | Critical"
    )
    created_at: datetime = Field(description="UTC timestamp of alert ingestion")
    updated_at: Optional[datetime] = Field(description="UTC timestamp of last update")

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def set_risk_category(self) -> "AlertResponse":
        """Derive risk_category from risk_score if not already set."""
        if self.risk_category is None and self.risk_score is not None:
            s = self.risk_score
            if s <= 25:
                self.risk_category = RiskCategory.LOW
            elif s <= 50:
                self.risk_category = RiskCategory.MEDIUM
            elif s <= 75:
                self.risk_category = RiskCategory.HIGH
            else:
                self.risk_category = RiskCategory.CRITICAL
        return self


class AlertEnrichedResponse(AlertResponse):
    """Extended response that includes threat intelligence context."""

    threat_intel: Optional[ThreatIntelSummary] = Field(
        default=None, description="Threat intelligence data for the source IP"
    )


# ── List wrapper ──────────────────────────────────────────────────────────────

class AlertListResponse(BaseModel):
    """Paginated alert list response."""

    total: int = Field(..., description="Total alerts matching the query filters")
    page_size: int = Field(..., description="Number of records in this page")
    alerts: List[AlertResponse]
