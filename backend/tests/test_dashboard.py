"""
Tests for Dashboard Analytics Endpoints.

GET /dashboard/summary
GET /dashboard/risk-distribution
GET /dashboard/recent-alerts
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.db import Base, get_db

# ── In-memory test database ───────────────────────────────────────────────────
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.pop(get_db, None)


client = TestClient(app)

# ── Helpers ───────────────────────────────────────────────────────────────────
ALERTS = [
    {"alert_type": "Brute Force",      "source_ip": "203.0.113.1",  "severity": "High"},
    {"alert_type": "Malware Detection","source_ip": "10.0.0.2",     "severity": "Critical"},
    {"alert_type": "Port Scan",        "source_ip": "192.168.1.3",  "severity": "Low"},
    {"alert_type": "Suspicious Login", "source_ip": "172.16.0.4",   "severity": "Medium"},
    {"alert_type": "Credential Stuffing","source_ip": "10.0.1.5",   "severity": "High"},
]


def _seed(n: int = 5):
    for payload in ALERTS[:n]:
        r = client.post("/alerts/", json=payload)
        assert r.status_code == 201, r.text


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Summary
# ─────────────────────────────────────────────────────────────────────────────
class TestDashboardSummary:
    def test_summary_returns_200(self):
        response = client.get("/dashboard/summary")
        assert response.status_code == 200

    def test_summary_empty_db(self):
        data = client.get("/dashboard/summary").json()
        assert data["total_alerts"] == 0
        assert data["open_alerts"] == 0
        assert data["avg_risk_score"] == 0.0

    def test_summary_has_all_required_fields(self):
        data = client.get("/dashboard/summary").json()
        required = {
            "total_alerts", "open_alerts", "investigating_alerts",
            "resolved_alerts", "critical_alerts", "high_alerts",
            "medium_alerts", "low_alerts", "malicious_ips",
            "suspicious_ips", "avg_risk_score",
        }
        assert required.issubset(data.keys())

    def test_summary_total_matches_seeded_count(self):
        _seed(5)
        data = client.get("/dashboard/summary").json()
        assert data["total_alerts"] == 5

    def test_summary_open_count(self):
        _seed(3)
        data = client.get("/dashboard/summary").json()
        # All freshly created alerts default to Open
        assert data["open_alerts"] == 3

    def test_summary_investigating_count_after_patch(self):
        _seed(2)
        # Move alert 1 to Investigating
        client.patch("/alerts/1/status", json={"status": "Investigating"})
        data = client.get("/dashboard/summary").json()
        assert data["investigating_alerts"] == 1
        assert data["open_alerts"] == 1

    def test_summary_resolved_count(self):
        _seed(3)
        client.patch("/alerts/1/status", json={"status": "Resolved"})
        client.patch("/alerts/2/status", json={"status": "Resolved"})
        data = client.get("/dashboard/summary").json()
        assert data["resolved_alerts"] == 2

    def test_summary_critical_count(self):
        _seed(5)
        data = client.get("/dashboard/summary").json()
        # ALERTS[1] is Critical severity
        assert data["critical_alerts"] >= 1

    def test_summary_avg_risk_score_is_numeric(self):
        _seed(3)
        data = client.get("/dashboard/summary").json()
        assert isinstance(data["avg_risk_score"], (int, float))
        assert 0.0 <= data["avg_risk_score"] <= 100.0


# ─────────────────────────────────────────────────────────────────────────────
# Risk Distribution
# ─────────────────────────────────────────────────────────────────────────────
class TestRiskDistribution:
    def test_risk_distribution_returns_200(self):
        response = client.get("/dashboard/risk-distribution")
        assert response.status_code == 200

    def test_risk_distribution_has_required_keys(self):
        data = client.get("/dashboard/risk-distribution").json()
        assert "total" in data
        assert "buckets" in data

    def test_risk_distribution_empty_db(self):
        data = client.get("/dashboard/risk-distribution").json()
        assert data["total"] == 0
        for bucket in data["buckets"]:
            assert bucket["count"] == 0
            assert bucket["pct"] == 0.0

    def test_risk_distribution_four_buckets(self):
        data = client.get("/dashboard/risk-distribution").json()
        assert len(data["buckets"]) == 4

    def test_risk_distribution_bucket_labels(self):
        data = client.get("/dashboard/risk-distribution").json()
        labels = {b["label"] for b in data["buckets"]}
        assert labels == {"Low", "Medium", "High", "Critical"}

    def test_risk_distribution_counts_sum_to_total(self):
        _seed(5)
        data = client.get("/dashboard/risk-distribution").json()
        bucket_sum = sum(b["count"] for b in data["buckets"])
        assert bucket_sum == data["total"]

    def test_risk_distribution_pct_sums_to_100_or_less(self):
        _seed(5)
        data = client.get("/dashboard/risk-distribution").json()
        total_pct = sum(b["pct"] for b in data["buckets"])
        assert abs(total_pct - 100.0) < 1.0   # allow rounding error


# ─────────────────────────────────────────────────────────────────────────────
# Recent Alerts
# ─────────────────────────────────────────────────────────────────────────────
class TestRecentAlerts:
    def test_recent_alerts_returns_200(self):
        response = client.get("/dashboard/recent-alerts")
        assert response.status_code == 200

    def test_recent_alerts_has_count_and_alerts(self):
        data = client.get("/dashboard/recent-alerts").json()
        assert "count" in data
        assert "alerts" in data

    def test_recent_alerts_empty_db(self):
        data = client.get("/dashboard/recent-alerts").json()
        assert data["count"] == 0
        assert data["alerts"] == []

    def test_recent_alerts_returns_seeded_data(self):
        _seed(5)
        data = client.get("/dashboard/recent-alerts").json()
        assert data["count"] == 5

    def test_recent_alerts_respects_limit(self):
        _seed(5)
        data = client.get("/dashboard/recent-alerts?limit=2").json()
        assert data["count"] <= 2
        assert len(data["alerts"]) <= 2

    def test_recent_alerts_default_limit_is_10(self):
        # Seed 5 alerts — all should appear with default limit
        _seed(5)
        data = client.get("/dashboard/recent-alerts").json()
        assert len(data["alerts"]) == 5

    def test_recent_alerts_ordered_newest_first(self):
        _seed(3)
        data = client.get("/dashboard/recent-alerts").json()
        alerts = data["alerts"]
        if len(alerts) > 1:
            # created_at of first should be >= second
            assert alerts[0]["created_at"] >= alerts[1]["created_at"]

    def test_recent_alerts_max_limit_50(self):
        response = client.get("/dashboard/recent-alerts?limit=100")
        assert response.status_code == 422   # exceeds max

    def test_recent_alerts_min_limit_1(self):
        response = client.get("/dashboard/recent-alerts?limit=0")
        assert response.status_code == 422   # below min
