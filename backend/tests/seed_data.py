"""
Seed script – populates the database with realistic sample security alerts.

Includes the five required alert types from Day 2:
  1. Brute Force Attack
  2. Malware Detection
  3. Suspicious Login
  4. Port Scan
  5. Credential Stuffing

Plus additional realistic alerts for a comprehensive demo dataset.

Usage (from the backend/ directory):
    python -m tests.seed_data
"""

import sys
import os

# Allow running from the backend/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import uuid
from datetime import datetime, timezone, timedelta

from app.database.db import Base, engine, SessionLocal
from app.models.alert import Alert, AlertStatus, SeverityLevel
from app.models.timeline import TimelineEvent
from app.services.risk_scoring import calculate_risk_score


def make_alert_id() -> str:
    return f"ALERT-{uuid.uuid4().hex[:8].upper()}"


# ── Day 2 Required Samples + Extended Realistic Dataset ─────────────────────
SAMPLE_ALERTS = [
    # 1. Brute Force Attack
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Brute Force",
        "source_ip":  "203.0.113.42",
        "severity":   SeverityLevel.High,
        "status":     AlertStatus.Open,
        "description": (
            "348 failed SSH login attempts in 60 seconds against auth-server-01. "
            "Originating from single external IP; lockout threshold exceeded."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(minutes=5),
        "updated_at": datetime.now(timezone.utc) - timedelta(minutes=5),
    },
    # 2. Malware Detection
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Malware Detection",
        "source_ip":  "10.0.1.55",
        "severity":   SeverityLevel.Critical,
        "status":     AlertStatus.Investigating,
        "description": (
            "Ransomware binary (SHA256: a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5) detected "
            "on endpoint WIN-DESK-055. File attempting to enumerate C:\\Users\\ shares."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=1),
        "updated_at": datetime.now(timezone.utc) - timedelta(minutes=30),
    },
    # 3. Suspicious Login
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Suspicious Login",
        "source_ip":  "185.220.101.9",
        "severity":   SeverityLevel.Medium,
        "status":     AlertStatus.Open,
        "description": (
            "User 'jsmith' authenticated from Tor exit node (185.220.101.9) at 02:17 UTC. "
            "Last known location: New York, USA. Current login: Minsk, Belarus."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=2),
    },
    # 4. Port Scan
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Port Scan",
        "source_ip":  "198.51.100.17",
        "severity":   SeverityLevel.Low,
        "status":     AlertStatus.Resolved,
        "description": (
            "Nmap-style SYN scan detected across 1024 ports on DMZ subnet 10.20.0.0/24. "
            "Scan completed in ~8s. Firewall blocked all probes beyond port 443."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=3),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=1),
    },
    # 5. Credential Stuffing
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Credential Stuffing",
        "source_ip":  "45.33.32.156",
        "severity":   SeverityLevel.High,
        "status":     AlertStatus.Investigating,
        "description": (
            "2,400 login attempts using leaked credential pairs from the 2023 "
            "RockYou2 breach against /api/v2/auth endpoint. 37 successful logins detected."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=4),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=3),
    },
    # 6. SQL Injection
    {
        "alert_id":   make_alert_id(),
        "alert_type": "SQL Injection",
        "source_ip":  "192.0.2.88",
        "severity":   SeverityLevel.Critical,
        "status":     AlertStatus.Open,
        "description": (
            "UNION-based SQLi payload detected in /api/users?id= query parameter. "
            "WAF blocked request; database error logs show attempted table enumeration."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=6),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=6),
    },
    # 7. Privilege Escalation
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Privilege Escalation",
        "source_ip":  "10.0.0.201",
        "severity":   SeverityLevel.Critical,
        "status":     AlertStatus.Open,
        "description": (
            "sudo -l abuse detected; user 'jdoe' gained root on prod-db-02 "
            "without MFA challenge. sudoers file tampering suspected."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=8),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=8),
    },
    # 8. Data Exfiltration
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Data Exfiltration",
        "source_ip":  "10.0.5.23",
        "severity":   SeverityLevel.High,
        "status":     AlertStatus.Investigating,
        "description": (
            "Unusual outbound transfer of 4.2 GB to external IP 91.189.94.4 over SFTP "
            "(port 22). Transfer initiated at 03:22 UTC outside business hours."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(hours=12),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=10),
    },
    # 9. Phishing
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Phishing",
        "source_ip":  "91.108.4.1",
        "severity":   SeverityLevel.Medium,
        "status":     AlertStatus.Resolved,
        "description": (
            "Phishing email with malicious macro-enabled .xlsm attachment blocked "
            "by email gateway. 12 employees targeted; 0 attachments opened."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
        "updated_at": datetime.now(timezone.utc) - timedelta(hours=20),
    },
    # 10. Reconnaissance
    {
        "alert_id":   make_alert_id(),
        "alert_type": "Reconnaissance",
        "source_ip":  "198.18.0.7",
        "severity":   SeverityLevel.Low,
        "status":     AlertStatus.Resolved,
        "description": (
            "OSINT-level DNS enumeration and WHOIS lookups detected for company domain. "
            "Consistent with automated scanner; no further activity observed."
        ),
        "created_at": datetime.now(timezone.utc) - timedelta(days=2),
        "updated_at": datetime.now(timezone.utc) - timedelta(days=2),
    },
]


def seed() -> None:
    """Create tables (if needed), compute risk scores, and insert sample alerts."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(Alert).count()
        if existing > 0:
            print(f"[seed] Database already contains {existing} alert(s). Skipping.")
            return

        for data in SAMPLE_ALERTS:
            # Compute risk score dynamically
            risk_score = calculate_risk_score(
                severity=data["severity"].value,
                alert_type=data["alert_type"],
                ti_score=0.5 if data["severity"] in (SeverityLevel.High, SeverityLevel.Critical) else 0.2,
            )
            data["risk_score"] = risk_score
            db.add(Alert(**data))

        db.commit()
        print(f"[seed] OK – Inserted {len(SAMPLE_ALERTS)} sample alerts.")
        print("[seed] Alerts inserted:")
        for a in SAMPLE_ALERTS:
            print(
                f"  • {a['alert_id']} | {a['alert_type']:<22} | "
                f"Severity: {a['severity'].value:<8} | "
                f"Status: {a['status'].value:<14} | "
                f"Risk: {a.get('risk_score', 0):.1f}"
            )
    finally:
        db.close()


if __name__ == "__main__":
    seed()
