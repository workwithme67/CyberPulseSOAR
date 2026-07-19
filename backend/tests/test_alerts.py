"""
Comprehensive unit test suite for the SOAR Alert Management API.
=================================================================

Test Coverage (Day 2)
----------------------
  TestHealthCheck       – Basic health-check endpoint.
  TestAlertCreation     – POST /alerts (valid, invalid IP, invalid severity, etc.)
  TestAlertRetrieval    – GET /alerts/{id}
  TestAlertListing      – GET /alerts with filters and pagination.
  TestStatusUpdate      – PATCH /alerts/{id}/status
  TestInputValidation   – IPv4-only and severity enum enforcement.
  TestRiskScoring       – Unit tests for the risk_scoring module.
  TestThreatIntelligence– Unit tests for the threat_intelligence module.

Run with:
    cd backend/
    pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.db import Base, get_db
from app.models.user import User, UserRole
from app.routes.deps import get_current_user
from app.services import risk_scoring, threat_intelligence

# ── Isolated in-memory test database (no file-path issues) ───────────────────
# StaticPool forces SQLAlchemy to reuse the same in-memory SQLite connection
# across all threads – required so setup_database fixture and test code share
# the same DB state.
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def mock_get_current_user():
    return User(
        id=999,
        username="test_admin",
        email="test_admin@example.com",
        role=UserRole.Admin,
        is_active=True,
    )


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop them after."""
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = mock_get_current_user
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# Shared test data
# ─────────────────────────────────────────────────────────────────────────────
VALID_PAYLOAD = {
    "alert_type":  "Brute Force",
    "source_ip":   "192.168.1.100",
    "severity":    "High",
    "description": "Multiple failed SSH login attempts detected.",
    "status":      "Open",
}


def create_one_alert(payload: dict | None = None) -> dict:
    """Helper: create a single alert and return the response JSON."""
    response = client.post("/alerts/", json=payload or VALID_PAYLOAD)
    assert response.status_code == 201, response.text
    return response.json()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Health Check
# ─────────────────────────────────────────────────────────────────────────────
class TestHealthCheck:
    def test_health_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200

    def test_health_response_has_status(self):
        response = client.get("/")
        assert response.json()["status"] == "running"

    def test_health_response_has_project(self):
        response = client.get("/")
        assert response.json()["project"] == "SOAR Incident Containment Engine"

    def test_health_response_has_version(self):
        response = client.get("/")
        assert "version" in response.json()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Alert Creation – POST /alerts
# ─────────────────────────────────────────────────────────────────────────────
class TestAlertCreation:
    def test_create_alert_returns_201(self):
        response = client.post("/alerts/", json=VALID_PAYLOAD)
        assert response.status_code == 201

    def test_create_alert_has_id(self):
        data = create_one_alert()
        assert "id" in data
        assert isinstance(data["id"], int)
        assert data["id"] >= 1

    def test_create_alert_has_alert_id(self):
        data = create_one_alert()
        assert "alert_id" in data
        assert data["alert_id"].startswith("ALERT-")

    def test_create_alert_has_created_at(self):
        data = create_one_alert()
        assert "created_at" in data
        assert data["created_at"] is not None

    def test_create_alert_has_updated_at(self):
        data = create_one_alert()
        assert "updated_at" in data
        assert data["updated_at"] is not None

    def test_create_alert_has_risk_score(self):
        data = create_one_alert()
        assert "risk_score" in data
        assert 0.0 <= data["risk_score"] <= 100.0

    def test_create_alert_preserves_alert_type(self):
        data = create_one_alert()
        assert data["alert_type"] == "Brute Force"

    def test_create_alert_preserves_source_ip(self):
        data = create_one_alert()
        assert data["source_ip"] == "192.168.1.100"

    def test_create_alert_preserves_severity(self):
        data = create_one_alert()
        assert data["severity"] == "High"

    def test_create_alert_default_status_is_open(self):
        payload = {**VALID_PAYLOAD}
        payload.pop("status", None)
        response = client.post("/alerts/", json=payload)
        assert response.json()["status"] == "Open"

    def test_create_alert_malware_detection(self):
        payload = {
            "alert_type": "Malware Detection",
            "source_ip":  "10.0.1.55",
            "severity":   "Critical",
            "description": "Ransomware detected on WIN-DESK-055.",
        }
        data = create_one_alert(payload)
        assert data["alert_type"] == "Malware Detection"
        assert data["severity"] == "Critical"

    def test_create_alert_suspicious_login(self):
        payload = {
            "alert_type": "Suspicious Login",
            "source_ip":  "185.220.101.9",
            "severity":   "Medium",
            "description": "Login from Tor exit node.",
        }
        data = create_one_alert(payload)
        assert data["alert_type"] == "Suspicious Login"

    def test_create_alert_port_scan(self):
        payload = {
            "alert_type": "Port Scan",
            "source_ip":  "198.51.100.17",
            "severity":   "Low",
        }
        data = create_one_alert(payload)
        assert data["alert_type"] == "Port Scan"

    def test_create_alert_credential_stuffing(self):
        payload = {
            "alert_type": "Credential Stuffing",
            "source_ip":  "45.33.32.156",
            "severity":   "High",
        }
        data = create_one_alert(payload)
        assert data["alert_type"] == "Credential Stuffing"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Input Validation
# ─────────────────────────────────────────────────────────────────────────────
class TestInputValidation:
    """IPv4 and severity field validation."""

    # -- Invalid IP address --------------------------------------------------
    def test_invalid_ip_string_returns_422(self):
        payload = {**VALID_PAYLOAD, "source_ip": "not-an-ip"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_partial_ip_returns_422(self):
        payload = {**VALID_PAYLOAD, "source_ip": "192.168.1"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_empty_ip_returns_422(self):
        payload = {**VALID_PAYLOAD, "source_ip": ""}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_ipv6_address_returns_422(self):
        payload = {**VALID_PAYLOAD, "source_ip": "2001:db8::1"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_hostname_returns_422(self):
        payload = {**VALID_PAYLOAD, "source_ip": "malicious.example.com"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    # -- Invalid severity ----------------------------------------------------
    def test_invalid_severity_extreme_returns_422(self):
        payload = {**VALID_PAYLOAD, "severity": "EXTREME"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_invalid_severity_number_returns_422(self):
        payload = {**VALID_PAYLOAD, "severity": "5"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    # -- Case-insensitive severity acceptance --------------------------------
    def test_severity_low_accepted(self):
        payload = {**VALID_PAYLOAD, "severity": "low"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        assert response.json()["severity"] == "Low"

    def test_severity_high_accepted(self):
        payload = {**VALID_PAYLOAD, "severity": "HIGH"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        assert response.json()["severity"] == "High"

    def test_severity_critical_accepted(self):
        payload = {**VALID_PAYLOAD, "severity": "critical"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        assert response.json()["severity"] == "Critical"

    # -- Missing required fields ---------------------------------------------
    def test_missing_alert_type_returns_422(self):
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "alert_type"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_missing_source_ip_returns_422(self):
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "source_ip"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_empty_body_returns_422(self):
        response = client.post("/alerts/", json={})
        assert response.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 4. Alert Retrieval – GET /alerts/{id}
# ─────────────────────────────────────────────────────────────────────────────
class TestAlertRetrieval:
    def test_get_existing_alert_returns_200(self):
        create_one_alert()
        response = client.get("/alerts/1")
        assert response.status_code == 200

    def test_get_alert_returns_correct_id(self):
        create_one_alert()
        data = client.get("/alerts/1").json()
        assert data["id"] == 1

    def test_get_alert_has_alert_id_field(self):
        create_one_alert()
        data = client.get("/alerts/1").json()
        assert "alert_id" in data
        assert data["alert_id"].startswith("ALERT-")

    def test_get_alert_has_risk_score_field(self):
        create_one_alert()
        data = client.get("/alerts/1").json()
        assert "risk_score" in data

    def test_get_nonexistent_alert_returns_404(self):
        response = client.get("/alerts/9999")
        assert response.status_code == 404

    def test_get_nonexistent_alert_has_detail(self):
        response = client.get("/alerts/9999")
        assert "detail" in response.json()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Alert Listing – GET /alerts
# ─────────────────────────────────────────────────────────────────────────────
class TestAlertListing:
    def _seed(self):
        payloads = [
            {"alert_type": "Port Scan",   "source_ip": "10.0.0.1", "severity": "Low"},
            {"alert_type": "SQL Injection", "source_ip": "10.0.0.2", "severity": "Critical"},
            {"alert_type": "DDoS",        "source_ip": "10.0.0.3", "severity": "High"},
        ]
        for p in payloads:
            client.post("/alerts/", json=p)

    def test_list_alerts_returns_200(self):
        response = client.get("/alerts/")
        assert response.status_code == 200

    def test_list_alerts_has_total_and_alerts(self):
        response = client.get("/alerts/")
        data = response.json()
        assert "total" in data
        assert "alerts" in data

    def test_list_alerts_empty_db(self):
        response = client.get("/alerts/")
        data = response.json()
        assert data["total"] == 0
        assert data["alerts"] == []

    def test_list_alerts_seeded_count(self):
        self._seed()
        data = client.get("/alerts/").json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 3

    def test_filter_by_severity_critical(self):
        self._seed()
        data = client.get("/alerts/?severity=Critical").json()
        assert all(a["severity"] == "Critical" for a in data["alerts"])

    def test_filter_by_severity_low(self):
        self._seed()
        data = client.get("/alerts/?severity=Low").json()
        assert all(a["severity"] == "Low" for a in data["alerts"])

    def test_filter_by_status_open(self):
        self._seed()
        data = client.get("/alerts/?status=Open").json()
        assert all(a["status"] == "Open" for a in data["alerts"])

    def test_pagination_limit(self):
        self._seed()
        data = client.get("/alerts/?limit=2").json()
        assert len(data["alerts"]) <= 2

    def test_pagination_skip(self):
        self._seed()
        data_full = client.get("/alerts/").json()
        data_skip = client.get("/alerts/?skip=1").json()
        # After skipping 1, we should have 1 fewer alert
        assert len(data_skip["alerts"]) == len(data_full["alerts"]) - 1


# ─────────────────────────────────────────────────────────────────────────────
# 6. Status Update – PATCH /alerts/{id}/status
# ─────────────────────────────────────────────────────────────────────────────
class TestStatusUpdate:
    def test_update_status_to_investigating(self):
        create_one_alert()
        response = client.patch("/alerts/1/status", json={"status": "Investigating"})
        assert response.status_code == 200
        assert response.json()["status"] == "Investigating"

    def test_update_status_to_resolved(self):
        create_one_alert()
        response = client.patch("/alerts/1/status", json={"status": "Resolved"})
        assert response.status_code == 200
        assert response.json()["status"] == "Resolved"

    def test_update_status_to_open(self):
        create_one_alert()
        client.patch("/alerts/1/status", json={"status": "Resolved"})
        response = client.patch("/alerts/1/status", json={"status": "Open"})
        assert response.status_code == 200
        assert response.json()["status"] == "Open"

    def test_update_status_nonexistent_alert_returns_404(self):
        response = client.patch("/alerts/9999/status", json={"status": "Resolved"})
        assert response.status_code == 404

    def test_update_status_invalid_value_returns_422(self):
        create_one_alert()
        response = client.patch("/alerts/1/status", json={"status": "CLOSED"})
        assert response.status_code == 422

    def test_update_status_case_insensitive(self):
        create_one_alert()
        response = client.patch("/alerts/1/status", json={"status": "investigating"})
        assert response.status_code == 200
        assert response.json()["status"] == "Investigating"

    def test_update_status_updates_updated_at(self):
        data = create_one_alert()
        old_updated_at = data["updated_at"]

        import time
        time.sleep(0.01)  # ensure timestamp differs

        response = client.patch("/alerts/1/status", json={"status": "Investigating"})
        new_updated_at = response.json()["updated_at"]
        # updated_at should be refreshed (may differ by milliseconds)
        assert new_updated_at >= old_updated_at


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk Scoring Module – Unit Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRiskScoring:
    def test_critical_severity_high_score(self):
        score = risk_scoring.calculate_risk_score(
            severity="Critical", alert_type="Ransomware", ti_score=1.0, is_off_hours=True
        )
        assert score >= 76, f"Expected Critical score ≥76, got {score}"

    def test_low_severity_low_score(self):
        score = risk_scoring.calculate_risk_score(
            severity="Low", alert_type="Reconnaissance", ti_score=0.0, is_off_hours=False
        )
        assert score <= 50, f"Expected Low score ≤50, got {score}"

    def test_score_is_clamped_to_100(self):
        score = risk_scoring.calculate_risk_score(
            severity="Critical", alert_type="Ransomware", ti_score=1.0, is_off_hours=True
        )
        assert score <= 100.0

    def test_score_is_non_negative(self):
        score = risk_scoring.calculate_risk_score(
            severity="Low", alert_type="Unknown Type", ti_score=0.0, is_off_hours=False
        )
        assert score >= 0.0

    def test_get_risk_level_low(self):
        assert risk_scoring.get_risk_level(15) == "Low"

    def test_get_risk_level_medium(self):
        assert risk_scoring.get_risk_level(40) == "Medium"

    def test_get_risk_level_high(self):
        assert risk_scoring.get_risk_level(60) == "High"

    def test_get_risk_level_critical(self):
        assert risk_scoring.get_risk_level(90) == "Critical"

    def test_get_risk_level_boundary_low_medium(self):
        assert risk_scoring.get_risk_level(25) == "Low"
        assert risk_scoring.get_risk_level(26) == "Medium"

    def test_get_risk_level_boundary_high_critical(self):
        assert risk_scoring.get_risk_level(75) == "High"
        assert risk_scoring.get_risk_level(76) == "Critical"

    def test_score_summary_has_all_keys(self):
        summary = risk_scoring.score_summary(65.0)
        assert "risk_score" in summary
        assert "risk_level" in summary
        assert "bands" in summary

    def test_score_summary_risk_level(self):
        summary = risk_scoring.score_summary(65.0)
        assert summary["risk_level"] == "High"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Threat Intelligence Service – Unit Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestThreatIntelligence:
    TEST_IP_BAD  = "203.0.113.42"
    TEST_IP_GOOD = "8.8.8.8"

    # AbuseIPDB ------------------------------------------------------------------
    def test_abuseipdb_returns_dict(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        assert isinstance(result, dict)

    def test_abuseipdb_has_required_keys(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        required = {
            "ip_address", "is_public", "abuse_confidence_score",
            "country_code", "isp", "total_reports", "source",
        }
        assert required.issubset(result.keys())

    def test_abuseipdb_ip_matches_query(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        assert result["ip_address"] == self.TEST_IP_BAD

    def test_abuseipdb_bad_ip_high_confidence(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        assert result["abuse_confidence_score"] >= 50

    def test_abuseipdb_good_ip_low_confidence(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_GOOD)
        assert result["abuse_confidence_score"] <= 30

    def test_abuseipdb_is_deterministic(self):
        r1 = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        r2 = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        assert r1["abuse_confidence_score"] == r2["abuse_confidence_score"]

    def test_abuseipdb_source_label(self):
        result = threat_intelligence.check_abuseipdb(self.TEST_IP_BAD)
        assert result["source"] == "AbuseIPDB (mock)"

    # VirusTotal -----------------------------------------------------------------
    def test_virustotal_returns_dict(self):
        result = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        assert isinstance(result, dict)

    def test_virustotal_has_required_keys(self):
        result = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        required = {
            "ip_address", "malicious_count", "suspicious_count",
            "harmless_count", "total_engines", "reputation", "source",
        }
        assert required.issubset(result.keys())

    def test_virustotal_bad_ip_has_malicious_detections(self):
        result = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        assert result["malicious_count"] > 0

    def test_virustotal_is_deterministic(self):
        r1 = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        r2 = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        assert r1["malicious_count"] == r2["malicious_count"]

    def test_virustotal_source_label(self):
        result = threat_intelligence.check_virustotal(self.TEST_IP_BAD)
        assert result["source"] == "VirusTotal (mock)"

    # Combined enrichment --------------------------------------------------------
    def test_enrich_ip_returns_dict(self):
        result = threat_intelligence.enrich_ip(self.TEST_IP_BAD)
        assert isinstance(result, dict)

    def test_enrich_ip_has_all_keys(self):
        result = threat_intelligence.enrich_ip(self.TEST_IP_BAD)
        assert "abuseipdb" in result
        assert "virustotal" in result
        assert "aggregate_confidence" in result
        assert "threat_verdict" in result

    def test_enrich_ip_bad_ip_verdict_malicious(self):
        result = threat_intelligence.enrich_ip(self.TEST_IP_BAD)
        assert result["threat_verdict"] in ("Malicious", "Suspicious")

    def test_enrich_ip_aggregate_in_range(self):
        result = threat_intelligence.enrich_ip(self.TEST_IP_BAD)
        assert 0 <= result["aggregate_confidence"] <= 100


# ─────────────────────────────────────────────────────────────────────────────
# 9. Playbook Auto-Trigger Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestPlaybookAutoTrigger:
    TEST_IP_BAD = "203.0.113.42"  # Known bad IP (Malicious verdict)

    def test_create_malicious_ip_triggers_block_ip_playbook(self):
        payload = {
            "alert_type":  "Brute Force",
            "source_ip":   self.TEST_IP_BAD,
            "severity":    "High",
            "description": "SSH brute-force attempts.",
        }
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        data = response.json()
        
        execs_response = client.get(f"/playbooks/executions?alert_id={data['alert_id']}")
        assert execs_response.status_code == 200
        execs = execs_response.json()
        assert len(execs) >= 1
        assert any(e["playbook_name"] == "block_ip" for e in execs)
        assert any(e["executed_by"] == "SOAR Automation" for e in execs)

    def test_create_ransomware_alert_triggers_host_isolation(self):
        payload = {
            "alert_type":  "Ransomware Activity",
            "source_ip":   "192.168.1.101",
            "severity":    "Medium",
            "description": "Ransomware activity.",
        }
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        data = response.json()
        
        execs_response = client.get(f"/playbooks/executions?alert_id={data['alert_id']}")
        assert execs_response.status_code == 200
        execs = execs_response.json()
        assert len(execs) >= 1
        assert any(e["playbook_name"] == "isolate_host" for e in execs)

    def test_create_critical_severity_alert_triggers_escalation(self):
        payload = {
            "alert_type":  "Suspicious Login",
            "source_ip":   "192.168.1.102",
            "severity":    "Critical",
            "description": "Critical logins.",
        }
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 201
        data = response.json()
        
        execs_response = client.get(f"/playbooks/executions?alert_id={data['alert_id']}")
        assert execs_response.status_code == 200
        execs = execs_response.json()
        assert len(execs) >= 1
        assert any(e["playbook_name"] == "escalate" for e in execs)

