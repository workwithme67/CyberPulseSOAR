"""
Comprehensive test suite for the SOAR Incident Containment Engine – Day 2.

Test classes
------------
TestHealthCheck      – Root endpoint and response structure.
TestCreateAlert      – Alert ingestion, IPv4 validation, field checks.
TestListAlerts       – Pagination, filtering, response structure.
TestGetAlert         – Single alert retrieval and 404 handling.
TestUpdateStatus     – PATCH status transitions and validation.
TestEnrichedAlert    – Enriched endpoint with threat intel.
TestRiskScoring      – Unit tests for the risk scoring engine.
TestThreatIntel      – Unit tests for mock threat intelligence functions.

Run with:
    pytest tests/test_alerts.py -v
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.db import Base, get_db
from app.services.risk_scoring import calculate_risk_score, get_risk_category, score_alert
from app.services.threat_intelligence import check_abuseipdb, check_virustotal, enrich_ip
from app.models.alert import SeverityLevel, AlertStatus

# ── Test database (in-memory SQLite) ─────────────────────────────────────────
TEST_DATABASE_URL = "sqlite:///./test_soar_day2.db"

test_engine = create_engine(
    TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop them after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


client = TestClient(app)

# ── Shared fixtures ───────────────────────────────────────────────────────────
VALID_ALERT = {
    "alert_type": "Brute Force Attack",
    "source_ip": "203.0.113.42",
    "severity": "HIGH",
    "description": "348 failed SSH login attempts detected.",
    "status": "OPEN",
}


def create_test_alert(overrides: dict = None) -> dict:
    """Helper: POST a valid alert and return the response JSON."""
    payload = {**VALID_ALERT, **(overrides or {})}
    resp = client.post("/alerts/", json=payload)
    assert resp.status_code == 201, f"Unexpected status: {resp.status_code} – {resp.text}"
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthCheck:
    def test_returns_200(self):
        assert client.get("/").status_code == 200

    def test_status_field(self):
        assert client.get("/").json()["status"] == "running"

    def test_project_field(self):
        assert "SOAR" in client.get("/").json()["project"]

    def test_version_field(self):
        assert client.get("/").json()["version"] == "0.2.0"

    def test_risk_bands_endpoint(self):
        resp = client.get("/risk-bands")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["bands"]) == 4


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Creation
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateAlert:
    def test_valid_alert_returns_201(self):
        resp = client.post("/alerts/", json=VALID_ALERT)
        assert resp.status_code == 201

    def test_response_contains_id(self):
        data = create_test_alert()
        assert "id" in data
        assert isinstance(data["id"], int)

    def test_response_contains_risk_score(self):
        data = create_test_alert()
        assert "risk_score" in data
        assert 0 <= data["risk_score"] <= 100

    def test_response_contains_risk_category(self):
        data = create_test_alert()
        assert data["risk_category"] in ["Low", "Medium", "High", "Critical"]

    def test_response_contains_created_at(self):
        data = create_test_alert()
        assert "created_at" in data

    def test_alert_type_preserved(self):
        data = create_test_alert()
        assert data["alert_type"] == "Brute Force Attack"

    def test_source_ip_preserved(self):
        data = create_test_alert()
        assert data["source_ip"] == "203.0.113.42"

    def test_severity_preserved(self):
        data = create_test_alert()
        assert data["severity"] == "HIGH"

    def test_default_status_is_open(self):
        # Omit status entirely so Pydantic uses the default (OPEN)
        payload = {k: v for k, v in VALID_ALERT.items() if k != "status"}
        resp = client.post("/alerts/", json=payload)
        assert resp.status_code == 201
        assert resp.json()["status"] == "OPEN"

    # ── IPv4 validation ──────────────────────────────────────────────────────

    def test_invalid_ip_format_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "source_ip": "not-an-ip"})
        assert resp.status_code == 422

    def test_ipv6_address_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "source_ip": "2001:db8::1"})
        assert resp.status_code == 422

    def test_incomplete_ip_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "source_ip": "192.168.1"})
        assert resp.status_code == 422

    def test_broadcast_ip_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "source_ip": "0.0.0.0"})
        assert resp.status_code == 422

    def test_valid_private_ip_accepted(self):
        """Private IPs should be accepted (internal alerts are valid)."""
        resp = client.post("/alerts/", json={**VALID_ALERT, "source_ip": "192.168.1.100"})
        assert resp.status_code == 201

    # ── Severity validation ───────────────────────────────────────────────────

    def test_invalid_severity_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "severity": "EXTREME"})
        assert resp.status_code == 422

    def test_all_severity_levels_accepted(self):
        for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            resp = client.post("/alerts/", json={**VALID_ALERT, "severity": sev})
            assert resp.status_code == 201, f"Failed for severity={sev}"

    # ── Missing fields ────────────────────────────────────────────────────────

    def test_missing_alert_type_returns_422(self):
        payload = {k: v for k, v in VALID_ALERT.items() if k != "alert_type"}
        assert client.post("/alerts/", json=payload).status_code == 422

    def test_missing_source_ip_returns_422(self):
        payload = {k: v for k, v in VALID_ALERT.items() if k != "source_ip"}
        assert client.post("/alerts/", json=payload).status_code == 422

    def test_alert_type_too_short_returns_422(self):
        resp = client.post("/alerts/", json={**VALID_ALERT, "alert_type": "X"})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Listing
# ═══════════════════════════════════════════════════════════════════════════════

class TestListAlerts:
    def _seed(self, count: int = 3):
        types = ["Port Scan", "SQL Injection", "DDoS Attack"]
        severities = ["LOW", "CRITICAL", "HIGH"]
        for i in range(count):
            create_test_alert({
                "alert_type": types[i % len(types)],
                "severity": severities[i % len(severities)],
                "source_ip": f"10.0.0.{i+1}",
            })

    def test_returns_200(self):
        assert client.get("/alerts/").status_code == 200

    def test_response_has_total_and_alerts(self):
        data = client.get("/alerts/").json()
        assert "total" in data
        assert "alerts" in data
        assert "page_size" in data

    def test_empty_list_on_fresh_db(self):
        data = client.get("/alerts/").json()
        assert data["total"] == 0
        assert data["alerts"] == []

    def test_correct_count_after_seeding(self):
        self._seed(3)
        data = client.get("/alerts/").json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 3

    def test_filter_by_severity(self):
        self._seed(3)
        data = client.get("/alerts/?severity=CRITICAL").json()
        assert all(a["severity"] == "CRITICAL" for a in data["alerts"])

    def test_filter_by_status(self):
        create_test_alert({"status": "OPEN"})
        create_test_alert({"status": "OPEN"})
        data = client.get("/alerts/?status=OPEN").json()
        assert all(a["status"] == "OPEN" for a in data["alerts"])

    def test_filter_by_alert_type_partial(self):
        self._seed(3)
        data = client.get("/alerts/?alert_type=Port").json()
        assert all("Port" in a["alert_type"] for a in data["alerts"])

    def test_filter_by_source_ip_exact(self):
        create_test_alert({"source_ip": "10.0.0.1"})
        create_test_alert({"source_ip": "10.0.0.2"})
        data = client.get("/alerts/?source_ip=10.0.0.1").json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["source_ip"] == "10.0.0.1"

    def test_pagination_limit(self):
        self._seed(3)
        data = client.get("/alerts/?limit=2").json()
        assert len(data["alerts"]) == 2

    def test_pagination_skip(self):
        self._seed(3)
        data = client.get("/alerts/?skip=2").json()
        assert len(data["alerts"]) == 1

    def test_limit_exceeds_100_returns_422(self):
        assert client.get("/alerts/?limit=200").status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Get Single Alert
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetAlert:
    def test_get_existing_alert_returns_200(self):
        created = create_test_alert()
        resp = client.get(f"/alerts/{created['id']}")
        assert resp.status_code == 200

    def test_response_contains_correct_id(self):
        created = create_test_alert()
        data = client.get(f"/alerts/{created['id']}").json()
        assert data["id"] == created["id"]

    def test_response_contains_risk_score(self):
        created = create_test_alert()
        data = client.get(f"/alerts/{created['id']}").json()
        assert "risk_score" in data

    def test_nonexistent_id_returns_404(self):
        assert client.get("/alerts/9999").status_code == 404

    def test_invalid_id_zero_returns_422(self):
        assert client.get("/alerts/0").status_code == 422

    def test_invalid_id_negative_returns_422(self):
        assert client.get("/alerts/-1").status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Status Update (PATCH)
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpdateStatus:
    def test_update_to_investigating_returns_200(self):
        created = create_test_alert()
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "INVESTIGATING"},
        )
        assert resp.status_code == 200

    def test_status_is_updated_in_response(self):
        created = create_test_alert()
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "INVESTIGATING"},
        )
        assert resp.json()["status"] == "INVESTIGATING"

    def test_update_to_resolved(self):
        created = create_test_alert()
        client.patch(f"/alerts/{created['id']}/status", json={"status": "INVESTIGATING"})
        resp = client.patch(f"/alerts/{created['id']}/status", json={"status": "RESOLVED"})
        assert resp.json()["status"] == "RESOLVED"

    def test_update_to_dismissed(self):
        created = create_test_alert()
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "DISMISSED"},
        )
        assert resp.json()["status"] == "DISMISSED"

    def test_same_status_returns_400(self):
        created = create_test_alert()  # default OPEN
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "OPEN"},
        )
        assert resp.status_code == 400

    def test_invalid_status_returns_422(self):
        created = create_test_alert()
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "PENDING"},
        )
        assert resp.status_code == 422

    def test_nonexistent_alert_returns_404(self):
        resp = client.patch("/alerts/9999/status", json={"status": "RESOLVED"})
        assert resp.status_code == 404

    def test_analyst_note_appended_to_description(self):
        created = create_test_alert()
        note = "Confirmed malicious activity from threat intel."
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "INVESTIGATING", "note": note},
        )
        assert note in resp.json()["description"]

    def test_updated_at_is_set_after_patch(self):
        created = create_test_alert()
        resp = client.patch(
            f"/alerts/{created['id']}/status",
            json={"status": "INVESTIGATING"},
        )
        assert resp.json()["updated_at"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Enriched Alert Endpoint
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnrichedAlert:
    def test_enriched_endpoint_returns_200(self):
        created = create_test_alert()
        resp = client.get(f"/alerts/{created['id']}/enriched")
        assert resp.status_code == 200

    def test_enriched_response_contains_threat_intel(self):
        created = create_test_alert()
        data = client.get(f"/alerts/{created['id']}/enriched").json()
        assert "threat_intel" in data
        ti = data["threat_intel"]
        assert "abuseipdb_score" in ti
        assert "virustotal_malicious" in ti
        assert "is_known_malicious" in ti

    def test_enriched_nonexistent_returns_404(self):
        assert client.get("/alerts/9999/enriched").status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Risk Scoring Engine Unit Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRiskScoring:
    def test_critical_severity_high_abuse_gives_high_score(self):
        score = calculate_risk_score("CRITICAL", abuseipdb_score=90, virustotal_malicious=30)
        assert score > 75

    def test_low_severity_clean_ip_gives_low_score(self):
        score = calculate_risk_score("LOW", abuseipdb_score=0, virustotal_malicious=0)
        assert score <= 25

    def test_score_is_capped_at_100(self):
        # With max inputs the formula gives ~97.5; the cap ensures it never exceeds 100
        score = calculate_risk_score("CRITICAL", abuseipdb_score=100, virustotal_malicious=90)
        assert score <= 100.0
        assert score >= 95.0  # Must be in Critical band

    def test_score_is_floored_at_0(self):
        score = calculate_risk_score("LOW", abuseipdb_score=0, virustotal_malicious=0)
        assert score >= 0

    def test_risk_category_low(self):
        assert get_risk_category(10) == "Low"

    def test_risk_category_medium(self):
        assert get_risk_category(40) == "Medium"

    def test_risk_category_high(self):
        assert get_risk_category(65) == "High"

    def test_risk_category_critical(self):
        assert get_risk_category(85) == "Critical"

    def test_risk_category_boundary_25(self):
        assert get_risk_category(25) == "Low"

    def test_risk_category_boundary_26(self):
        assert get_risk_category(26) == "Medium"

    def test_risk_category_boundary_76(self):
        assert get_risk_category(76) == "Critical"

    def test_score_alert_returns_dict_with_required_keys(self):
        enrichment = {
            "abuseipdb_score": 50,
            "abuseipdb_reports": 10,
            "virustotal_malicious": 5,
            "virustotal_suspicious": 2,
            "is_known_malicious": False,
        }
        result = score_alert("HIGH", enrichment)
        assert "score" in result
        assert "category" in result
        assert "breakdown" in result

    def test_medium_severity_medium_threat_is_medium(self):
        score = calculate_risk_score("MEDIUM", abuseipdb_score=30, virustotal_malicious=3)
        assert 26 <= score <= 75


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Intelligence Unit Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelligence:
    KNOWN_BAD_IP = "185.220.101.9"
    CLEAN_IP = "8.8.8.8"

    def test_abuseipdb_returns_dict(self):
        result = check_abuseipdb(self.CLEAN_IP)
        assert isinstance(result, dict)

    def test_abuseipdb_has_required_fields(self):
        result = check_abuseipdb(self.CLEAN_IP)
        for field in ["ipAddress", "abuseConfidenceScore", "totalReports", "countryCode"]:
            assert field in result

    def test_abuseipdb_score_range(self):
        result = check_abuseipdb(self.CLEAN_IP)
        assert 0 <= result["abuseConfidenceScore"] <= 100

    def test_known_bad_ip_has_high_abuse_score(self):
        result = check_abuseipdb(self.KNOWN_BAD_IP)
        assert result["abuseConfidenceScore"] >= 65

    def test_virustotal_returns_dict(self):
        result = check_virustotal(self.CLEAN_IP)
        assert isinstance(result, dict)

    def test_virustotal_has_required_fields(self):
        result = check_virustotal(self.CLEAN_IP)
        for field in ["malicious", "suspicious", "harmless", "undetected"]:
            assert field in result

    def test_virustotal_known_bad_has_malicious_detections(self):
        result = check_virustotal(self.KNOWN_BAD_IP)
        assert result["malicious"] >= 10

    def test_enrich_ip_combines_both_sources(self):
        result = enrich_ip(self.CLEAN_IP)
        assert "abuseipdb" in result
        assert "virustotal" in result
        assert "is_known_malicious" in result
        assert "abuseipdb_score" in result
        assert "virustotal_malicious" in result

    def test_mock_is_deterministic(self):
        """Same IP must always produce the same scores."""
        r1 = check_abuseipdb("10.0.0.1")
        r2 = check_abuseipdb("10.0.0.1")
        assert r1["abuseConfidenceScore"] == r2["abuseConfidenceScore"]

    def test_different_ips_different_scores(self):
        """Different IPs should (usually) produce different scores."""
        r1 = check_abuseipdb("10.0.0.1")
        r2 = check_abuseipdb("10.0.0.2")
        # Not guaranteed but extremely unlikely to be equal for different IPs
        assert r1["abuseConfidenceScore"] != r2["abuseConfidenceScore"]
