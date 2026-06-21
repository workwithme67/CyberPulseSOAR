"""
Seed script – Day 2 expanded sample data (20 realistic security alerts).

Usage (from the backend/ directory):
    python tests/seed_data.py

The script is idempotent: it skips insertion if data already exists,
or drops + recreates when --reset flag is passed.

Covers alert types:
  Brute Force Attack, Port Scan, SQL Injection, DDoS, Malware Detection,
  Phishing, Privilege Escalation, Data Exfiltration, Insider Threat,
  Reconnaissance, Credential Stuffing, Ransomware, XSS Attempt,
  Zero-Day Exploit, Command & Control, DNS Tunneling, Man-in-the-Middle,
  Supply Chain Attack, API Abuse, Lateral Movement
"""

import sys
import os
import argparse

# Allow running from the backend/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta

from app.database.db import engine, Base, SessionLocal
from app.models.alert import Alert, SeverityLevel, AlertStatus
from app.services.threat_intelligence import enrich_ip
from app.services.risk_scoring import score_alert


SAMPLE_ALERTS = [
    # ── 1. Brute Force ────────────────────────────────────────────────────────
    {
        "alert_type": "Brute Force Attack",
        "source_ip": "203.0.113.42",
        "severity": SeverityLevel.HIGH,
        "description": "348 failed SSH login attempts in 60 seconds against auth-server-01.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(minutes=5),
    },
    # ── 2. Port Scan ──────────────────────────────────────────────────────────
    {
        "alert_type": "Port Scan",
        "source_ip": "198.51.100.17",
        "severity": SeverityLevel.MEDIUM,
        "description": "Nmap-style SYN scan across 1024 ports on DMZ subnet 10.0.1.0/24.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(minutes=30),
    },
    # ── 3. SQL Injection ──────────────────────────────────────────────────────
    {
        "alert_type": "SQL Injection",
        "source_ip": "192.0.2.88",
        "severity": SeverityLevel.CRITICAL,
        "description": "UNION-based injection payload detected in /api/users?id= parameter.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=1),
    },
    # ── 4. DDoS ───────────────────────────────────────────────────────────────
    {
        "alert_type": "DDoS Attack",
        "source_ip": "45.33.32.156",
        "severity": SeverityLevel.CRITICAL,
        "description": "SYN flood: 85,000 packets/sec targeting load balancer on port 443.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
    },
    # ── 5. Malware ────────────────────────────────────────────────────────────
    {
        "alert_type": "Malware Detection",
        "source_ip": "10.0.1.55",
        "severity": SeverityLevel.HIGH,
        "description": "Ransomware binary (SHA256: a3f8cc...) detected on endpoint WIN-DESK-055.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=3),
    },
    # ── 6. Phishing ───────────────────────────────────────────────────────────
    {
        "alert_type": "Phishing Attempt",
        "source_ip": "185.220.101.9",
        "severity": SeverityLevel.MEDIUM,
        "description": "Phishing email with macro-enabled attachment blocked at mail gateway.",
        "status": AlertStatus.RESOLVED,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=6),
    },
    # ── 7. Privilege Escalation ───────────────────────────────────────────────
    {
        "alert_type": "Privilege Escalation",
        "source_ip": "10.0.0.201",
        "severity": SeverityLevel.CRITICAL,
        "description": "sudo -l abuse: user 'jdoe' gained root on prod-db-02 without MFA.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=8),
    },
    # ── 8. Data Exfiltration ──────────────────────────────────────────────────
    {
        "alert_type": "Data Exfiltration",
        "source_ip": "10.0.5.23",
        "severity": SeverityLevel.HIGH,
        "description": "Unusual outbound transfer: 4.2 GB to external IP over SSH port 22.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=12),
    },
    # ── 9. Insider Threat ────────────────────────────────────────────────────
    {
        "alert_type": "Insider Threat",
        "source_ip": "10.10.0.88",
        "severity": SeverityLevel.HIGH,
        "description": "Employee accessed 1,200+ sensitive PII records at 2 AM outside working hours.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
    },
    # ── 10. Reconnaissance ───────────────────────────────────────────────────
    {
        "alert_type": "Reconnaissance",
        "source_ip": "198.18.0.7",
        "severity": SeverityLevel.LOW,
        "description": "DNS enumeration and WHOIS lookups detected for company domain assets.",
        "status": AlertStatus.DISMISSED,
        "created_at": datetime.now(timezone.utc) - timedelta(days=2),
    },
    # ── 11. Credential Stuffing ───────────────────────────────────────────────
    {
        "alert_type": "Credential Stuffing",
        "source_ip": "162.247.74.200",
        "severity": SeverityLevel.HIGH,
        "description": "12,000 login attempts using breached credentials from HaveIBeenPwned list.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=4),
    },
    # ── 12. Ransomware ────────────────────────────────────────────────────────
    {
        "alert_type": "Ransomware Activity",
        "source_ip": "5.188.10.76",
        "severity": SeverityLevel.CRITICAL,
        "description": "LockBit 3.0 variant encrypting files on network share \\\\FILESERVER01\\Finance.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=1, minutes=30),
    },
    # ── 13. XSS ──────────────────────────────────────────────────────────────
    {
        "alert_type": "XSS Attempt",
        "source_ip": "91.108.56.100",
        "severity": SeverityLevel.MEDIUM,
        "description": "Reflected XSS payload detected in search parameter of customer portal.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=5),
    },
    # ── 14. Zero-Day ─────────────────────────────────────────────────────────
    {
        "alert_type": "Zero-Day Exploit",
        "source_ip": "194.165.16.10",
        "severity": SeverityLevel.CRITICAL,
        "description": "Exploitation of CVE-2024-XXXX on Apache Struts 2.5.x – RCE achieved.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=7),
    },
    # ── 15. C2 ───────────────────────────────────────────────────────────────
    {
        "alert_type": "Command & Control",
        "source_ip": "185.220.101.9",
        "severity": SeverityLevel.CRITICAL,
        "description": "Beacon traffic to known Cobalt Strike C2 infrastructure detected.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=9),
    },
    # ── 16. DNS Tunneling ─────────────────────────────────────────────────────
    {
        "alert_type": "DNS Tunneling",
        "source_ip": "10.0.3.17",
        "severity": SeverityLevel.HIGH,
        "description": "Abnormal DNS TXT record queries suggesting data exfil via DNS tunneling.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=14),
    },
    # ── 17. MITM ─────────────────────────────────────────────────────────────
    {
        "alert_type": "Man-in-the-Middle",
        "source_ip": "10.0.2.99",
        "severity": SeverityLevel.HIGH,
        "description": "ARP spoofing detected between gateway 10.0.0.1 and workstation 10.0.2.50.",
        "status": AlertStatus.RESOLVED,
        "created_at": datetime.now(timezone.utc) - timedelta(days=3),
    },
    # ── 18. Supply Chain ─────────────────────────────────────────────────────
    {
        "alert_type": "Supply Chain Attack",
        "source_ip": "203.0.113.199",
        "severity": SeverityLevel.CRITICAL,
        "description": "Malicious npm package 'event-stream-fix' injected into CI/CD pipeline.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(days=1, hours=6),
    },
    # ── 19. API Abuse ─────────────────────────────────────────────────────────
    {
        "alert_type": "API Abuse",
        "source_ip": "198.51.100.88",
        "severity": SeverityLevel.MEDIUM,
        "description": "Rate limit exceeded: 50,000 API calls in 10 min from single IP to /v1/users.",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=20),
    },
    # ── 20. Lateral Movement ──────────────────────────────────────────────────
    {
        "alert_type": "Lateral Movement",
        "source_ip": "10.0.4.12",
        "severity": SeverityLevel.HIGH,
        "description": "Mimikatz-style credential dumping followed by RDP connections to 6 hosts.",
        "status": AlertStatus.INVESTIGATING,
        "created_at": datetime.now(timezone.utc) - timedelta(hours=11),
    },
]


def seed(reset: bool = False) -> None:
    """Create tables and insert sample alerts."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(Alert).count()

        if existing > 0 and not reset:
            print(f"[seed] Database already contains {existing} alerts. Use --reset to re-seed.")
            return

        if reset and existing > 0:
            db.query(Alert).delete()
            db.commit()
            print(f"[seed] Cleared {existing} existing alerts.")

        for data in SAMPLE_ALERTS:
            # Run enrichment + risk scoring for each seed alert
            enrichment = enrich_ip(data["source_ip"])
            scoring = score_alert(
                severity=data["severity"], enrichment=enrichment
            )
            alert = Alert(
                alert_type=data["alert_type"],
                source_ip=data["source_ip"],
                severity=data["severity"],
                description=data["description"],
                status=data["status"],
                risk_score=scoring["score"],
                created_at=data["created_at"],
                updated_at=data["created_at"],
            )
            db.add(alert)

        db.commit()
        print(f"[seed] OK - Inserted {len(SAMPLE_ALERTS)} sample alerts with risk scores.")

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the SOAR database with sample alerts.")
    parser.add_argument("--reset", action="store_true", help="Drop existing alerts before seeding.")
    args = parser.parse_args()
    seed(reset=args.reset)
