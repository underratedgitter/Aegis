"""Incidents that stall in the approval pipeline can be closed, by an operator or by expiry."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.control_plane import app, store
from aegis.incidents import IncidentEngine
from aegis.settings import Settings
from aegis.storage import Store

RECOMMENDATION = {"action": "clear_fault", "target": "checkout", "parameters": {"fault": "latency"}}


@pytest.fixture
def client():
    return TestClient(app)


def make_incident(incident_id, status):
    store.upsert_incident(incident_id, "Stuck", "high", f"service:{incident_id}", {"n": 0})
    store.merge_incident(incident_id, {"recommendation": RECOMMENDATION}, status=status)
    return incident_id


def resolve(client, incident_id, **body):
    return client.post(
        f"/api/incidents/{incident_id}/resolve", json={"approver": "ops", "note": "fixed", **body}
    )


class TestManualResolve:
    @pytest.mark.parametrize(
        "status", ["open", "investigating", "recommendation_pending", "approved"]
    )
    def test_an_operator_can_close_a_stalled_incident_with_a_note(self, client, status):
        incident_id = make_incident(f"inc-res-{status}", status)

        response = resolve(client, incident_id, note="rolled back by hand")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "resolved"
        assert body["resolved_at"]
        assert body["data"]["resolution"]["note"] == "rolled back by hand"
        assert body["data"]["resolution"]["previous_status"] == status
        event = body["events"][-1]
        assert event["kind"] == "resolved"
        assert "ops" in event["message"]
        assert "rolled back by hand" in event["message"]
        entries, _ = store.audit_entries(incident_id=incident_id)
        assert entries[0]["action"] == "incident_resolve"
        assert entries[0]["note"] == "rolled back by hand"

    def test_a_resolved_approved_incident_can_no_longer_be_executed(self, client):
        incident_id = make_incident("inc-res-exec", "approved")
        assert resolve(client, incident_id).status_code == 200

        response = client.post(f"/api/incidents/{incident_id}/execute", json={"approver": "ops"})

        assert response.status_code == 409

    def test_an_incident_with_a_remediation_in_flight_is_refused(self, client):
        incident_id = make_incident("inc-res-flight", "executing")

        response = resolve(client, incident_id)

        assert response.status_code == 409
        assert store.get_incident(incident_id)["status"] == "executing"

    @pytest.mark.parametrize("status", ["resolved", "closed"])
    def test_a_finished_incident_is_a_409(self, client, status):
        incident_id = make_incident(f"inc-res-done-{status}", status)

        assert resolve(client, incident_id).status_code == 409

    def test_an_unknown_incident_is_a_404(self, client):
        assert resolve(client, "inc-res-missing").status_code == 404

    @pytest.mark.parametrize("body", [{"approver": "ops"}, {"approver": "ops", "note": ""}])
    def test_a_note_is_required(self, client, body):
        incident_id = make_incident("inc-res-nonote", "recommendation_pending")

        response = client.post(f"/api/incidents/{incident_id}/resolve", json=body)

        assert response.status_code == 422
        assert store.get_incident(incident_id)["status"] == "recommendation_pending"

    def test_it_needs_the_api_key_when_one_is_configured(self, client, monkeypatch):
        monkeypatch.setattr(control_plane, "API_KEY", "k")
        incident_id = make_incident("inc-res-auth", "recommendation_pending")

        assert resolve(client, incident_id).status_code == 401
        assert store.get_incident(incident_id)["status"] == "recommendation_pending"


class TestResolveButton:
    """The UI has no JS test harness, so check the shipped files statically."""

    STATIC = Path(control_plane.__file__).parent / "static"
    APP_JS = (STATIC / "app.js").read_text()

    def test_the_button_is_delegated_and_gated_on_status(self):
        assert 'canResolve ? actionButton("resolve"' in self.APP_JS
        assert "resolve: ({id}) => resolveIncident(id)" in self.APP_JS
        assert "const canResolve = canInvestigate;" in self.APP_JS

    def test_resolving_asks_for_confirmation_and_a_note_first(self):
        body = self.APP_JS.split("async function resolveIncident(id)")[1].split("\n}\n")[0]
        assert body.index("confirmDialog") < body.index("/resolve")
        assert "note" in body

    def test_cancelling_the_dialog_is_not_blocked_by_the_required_note(self):
        index = (self.STATIC / "index.html").read_text()
        assert 'id="confirm-cancel" class="btn btn-ghost" formnovalidate' in index


@pytest.fixture
def engine(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", resolution_cycles=2
    )
    local = Store(settings.db_path)
    yield IncidentEngine(settings, local, telemetry=None), local  # type: ignore[arg-type]
    local.close()


def pending_incident(local, status="recommendation_pending"):
    local.upsert_incident("inc-1", "Stuck", "high", "service:x", {"n": 0})
    local.merge_incident("inc-1", {"recommendation": RECOMMENDATION}, status=status)


class TestRecommendationExpiry:
    def test_a_quiet_pending_recommendation_expires_after_the_resolution_cycles(self, engine):
        runner, local = engine
        pending_incident(local)

        runner._resolve_missing(set())
        assert local.get_incident("inc-1")["status"] == "recommendation_pending"
        runner._resolve_missing(set())

        incident = local.get_incident("inc-1")
        assert incident["status"] == "resolved"
        assert incident["resolved_at"]
        last = local.events("inc-1")[-1]
        assert last["kind"] == "recommendation_expired"
        assert "expired" in last["message"]

    def test_a_signal_that_keeps_firing_keeps_the_recommendation_alive(self, engine):
        runner, local = engine
        pending_incident(local)

        runner._resolve_missing(set())
        runner._resolve_missing({"inc-1"})
        runner._resolve_missing(set())

        assert local.get_incident("inc-1")["status"] == "recommendation_pending"

    def test_an_approval_between_cycles_wins_over_expiry(self, engine):
        runner, local = engine
        pending_incident(local)
        runner._resolve_missing(set())

        local.transition_status("inc-1", "recommendation_pending", "approved")
        runner._resolve_missing(set())

        assert local.get_incident("inc-1")["status"] == "approved"

    @pytest.mark.parametrize("status", ["approved", "executing", "investigating"])
    def test_work_in_flight_is_never_expired(self, engine, status):
        runner, local = engine
        pending_incident(local, status)

        for _ in range(5):
            runner._resolve_missing(set())

        assert local.get_incident("inc-1")["status"] == status

    def test_an_unreadable_signal_does_not_expire_the_recommendation(self, engine):
        runner, local = engine
        pending_incident(local)

        for _ in range(5):
            runner._resolve_missing(set(), {"service:x"})

        assert local.get_incident("inc-1")["status"] == "recommendation_pending"
