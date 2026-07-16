"""
Tests for the Incident Timeline System.

Tests cover:
  - Timeline auto-created on alert creation (AlertCreated, AlertEnriched, RiskCalculated).
  - GET /alerts/{id}/timeline response structure.
  - StatusUpdated event on PATCH /alerts/{id}/status.
  - AlertDeleted event + cascade on DELETE /alerts/{id}.
  - Timeline service unit tests (add_event, get_timeline).
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.db import Base, get_db
from app.models.timeline import EventType
from app.services import timeline_service

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

VALID_ALERT = {
    "alert_type":  "Brute Force",
    "source_ip":   "192.168.1.100",
    "severity":    "High",
    "description": "SSH login attempts.",
}


def _create_alert(payload=None) -> dict:
    r = client.post("/alerts/", json=payload or VALID_ALERT)
    assert r.status_code == 201, r.text
    return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Timeline API Endpoint Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestTimelineEndpoint:
    def test_timeline_returns_200(self):
        _create_alert()
        response = client.get("/alerts/1/timeline")
        assert response.status_code == 200

    def test_timeline_nonexistent_alert_returns_404(self):
        response = client.get("/alerts/9999/timeline")
        assert response.status_code == 404

    def test_timeline_has_required_fields(self):
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        required = {"alert_id", "alert_type", "source_ip", "severity",
                    "status", "risk_score", "threat_verdict", "created_at", "events"}
        assert required.issubset(data.keys())

    def test_timeline_events_is_list(self):
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert isinstance(data["events"], list)

    def test_timeline_has_three_events_on_creation(self):
        """AlertCreated + AlertEnriched + RiskCalculated = 3 events."""
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert len(data["events"]) == 3

    def test_timeline_first_event_is_alert_created(self):
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert data["events"][0]["event_type"] == "AlertCreated"

    def test_timeline_second_event_is_alert_enriched(self):
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert data["events"][1]["event_type"] == "AlertEnriched"

    def test_timeline_third_event_is_risk_calculated(self):
        _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert data["events"][2]["event_type"] == "RiskCalculated"

    def test_timeline_event_has_required_fields(self):
        _create_alert()
        event = client.get("/alerts/1/timeline").json()["events"][0]
        required = {"id", "alert_id", "event_type", "description", "occurred_at"}
        assert required.issubset(event.keys())

    def test_timeline_events_are_chronological(self):
        _create_alert()
        events = client.get("/alerts/1/timeline").json()["events"]
        timestamps = [e["occurred_at"] for e in events]
        assert timestamps == sorted(timestamps)

    def test_timeline_alert_id_matches(self):
        alert = _create_alert()
        data = client.get("/alerts/1/timeline").json()
        assert data["alert_id"] == alert["alert_id"]


# ─────────────────────────────────────────────────────────────────────────────
# Status Update Timeline Event
# ─────────────────────────────────────────────────────────────────────────────
class TestStatusUpdateTimeline:
    def test_status_update_adds_event(self):
        _create_alert()
        client.patch("/alerts/1/status", json={"status": "Investigating"})
        events = client.get("/alerts/1/timeline").json()["events"]
        # Should now have 4 events (3 creation + 1 status update)
        assert len(events) == 4

    def test_status_update_event_type(self):
        _create_alert()
        client.patch("/alerts/1/status", json={"status": "Investigating"})
        events = client.get("/alerts/1/timeline").json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "StatusUpdated" in event_types

    def test_status_update_event_description_contains_transition(self):
        _create_alert()
        client.patch("/alerts/1/status", json={"status": "Resolved"})
        events = client.get("/alerts/1/timeline").json()["events"]
        status_event = next(e for e in events if e["event_type"] == "StatusUpdated")
        assert "Resolved" in status_event["description"]

    def test_multiple_status_updates_add_multiple_events(self):
        _create_alert()
        client.patch("/alerts/1/status", json={"status": "Investigating"})
        client.patch("/alerts/1/status", json={"status": "Resolved"})
        events = client.get("/alerts/1/timeline").json()["events"]
        status_events = [e for e in events if e["event_type"] == "StatusUpdated"]
        assert len(status_events) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Delete Alert Timeline Behaviour
# ─────────────────────────────────────────────────────────────────────────────
class TestDeleteTimeline:
    def test_delete_returns_200(self):
        _create_alert()
        response = client.delete("/alerts/1")
        assert response.status_code == 200

    def test_delete_response_has_message(self):
        _create_alert()
        data = client.delete("/alerts/1").json()
        assert "message" in data
        assert "alert_id" in data

    def test_delete_removes_alert(self):
        _create_alert()
        client.delete("/alerts/1")
        response = client.get("/alerts/1")
        assert response.status_code == 404

    def test_delete_nonexistent_alert_returns_404(self):
        response = client.delete("/alerts/9999")
        assert response.status_code == 404

    def test_delete_reduces_total_count(self):
        _create_alert()
        _create_alert()
        before = client.get("/dashboard/summary").json()["total_alerts"]
        client.delete("/alerts/1")
        after = client.get("/dashboard/summary").json()["total_alerts"]
        assert after == before - 1

    def test_deleted_alert_not_in_list(self):
        _create_alert()
        client.delete("/alerts/1")
        data = client.get("/alerts/").json()
        assert all(a["id"] != 1 for a in data["alerts"])


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Service Unit Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestTimelineService:
    def _get_db(self):
        return TestingSessionLocal()

    def test_add_event_returns_timeline_event(self):
        _create_alert()
        db = self._get_db()
        try:
            event = timeline_service.add_event(
                db=db,
                alert_db_id=1,
                alert_id="ALERT-TEST0001",
                event_type=EventType.StatusUpdated,
                description="Test event",
            )
            assert event.id is not None
            assert event.event_type == EventType.StatusUpdated
        finally:
            db.close()

    def test_add_event_with_metadata(self):
        _create_alert()
        db = self._get_db()
        try:
            meta = {"old_status": "Open", "new_status": "Investigating"}
            event = timeline_service.add_event(
                db=db,
                alert_db_id=1,
                alert_id="ALERT-TEST0001",
                event_type=EventType.StatusUpdated,
                description="Status changed",
                metadata=meta,
            )
            assert event.metadata_json is not None
            stored = json.loads(event.metadata_json)
            assert stored["old_status"] == "Open"
        finally:
            db.close()

    def test_get_timeline_returns_list(self):
        _create_alert()
        db = self._get_db()
        try:
            events = timeline_service.get_timeline(db=db, alert_db_id=1)
            assert isinstance(events, list)
            assert len(events) >= 3
        finally:
            db.close()

    def test_get_timeline_ordered_chronologically(self):
        _create_alert()
        db = self._get_db()
        try:
            events = timeline_service.get_timeline(db=db, alert_db_id=1)
            timestamps = [e.occurred_at for e in events]
            assert timestamps == sorted(timestamps)
        finally:
            db.close()

    def test_get_timeline_empty_for_unknown_alert(self):
        db = self._get_db()
        try:
            events = timeline_service.get_timeline(db=db, alert_db_id=99999)
            assert events == []
        finally:
            db.close()
