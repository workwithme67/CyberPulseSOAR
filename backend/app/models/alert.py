"""
SQLAlchemy ORM model for security alerts – Day 2 Enhanced Schema.

Fields
------
id          : Auto-incrementing primary key.
alert_type  : Category of the alert (e.g. "Brute Force", "Port Scan").
source_ip   : IPv4 address that triggered the alert.
severity    : Enumerated severity – LOW | MEDIUM | HIGH | CRITICAL.
status      : Workflow state – OPEN | INVESTIGATING | RESOLVED | DISMISSED.
description : Optional free-text context provided by the detection source.
risk_score  : Computed integer 0-100 from the risk scoring engine.
created_at  : UTC datetime when the alert was first ingested.
updated_at  : UTC datetime of the most recent update (auto-updated on change).
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum as SAEnum, Float
from app.database.db import Base
import enum


# ── Enumerations ────────────────────────────────────────────────────────────


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"   # Day 2: renamed IN_PROGRESS → INVESTIGATING
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class RiskCategory(str, enum.Enum):
    """Human-readable label derived from the 0-100 risk score."""
    LOW = "Low"          # 0–25
    MEDIUM = "Medium"    # 26–50
    HIGH = "High"        # 51–75
    CRITICAL = "Critical"  # 76–100


# ── ORM Model ───────────────────────────────────────────────────────────────


class Alert(Base):
    """ORM representation of a security alert stored in the database."""

    __tablename__ = "alerts"

    id: int = Column(Integer, primary_key=True, index=True, autoincrement=True)

    alert_type: str = Column(String(100), nullable=False, index=True)

    # IPv4 only (Day 2 adds explicit IPv4-only validation in Pydantic)
    source_ip: str = Column(String(45), nullable=False, index=True)

    severity: str = Column(
        SAEnum(SeverityLevel, name="severitylevel"),
        nullable=False,
        default=SeverityLevel.MEDIUM,
        index=True,
    )

    status: str = Column(
        SAEnum(AlertStatus, name="alertstatus"),
        nullable=False,
        default=AlertStatus.OPEN,
        index=True,
    )

    description: str = Column(String(500), nullable=True)

    # Risk scoring (populated by the risk engine at alert creation)
    risk_score: float = Column(Float, nullable=True, default=0.0)

    # Timestamps
    created_at: datetime = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime = Column(
        DateTime(timezone=True),
        nullable=True,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} type={self.alert_type!r} "
            f"severity={self.severity} status={self.status} "
            f"risk_score={self.risk_score}>"
        )
