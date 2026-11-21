"""Remediation failures are recorded, never retried, and never erase concurrent evidence."""

import httpx
import pytest

from aegis.remediation import RemediationError, RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store


class OkResponse:
    text = "not json"

    def raise_for_status(self):
        return None

    def json(self):
        raise ValueError("not json")


def _executor(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        checkout_url="http://checkout",
        inventory_url="http://inventory",
        api_key="test-key",
    )
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", "dependency:inventory", {"n": 0})
    recommendation = {
        "action": "clear_fault",
        "target": "inventory",
        "parameters": {"fault": "dependency"},
    }
    store.merge_incident(
        "inc-1",
        {"recommendation": recommendation, "approval": {"approver": "op", "recommendation": recommendation}},
        status="approved",
    )
    return RemediationExecutor(settings, store), store


def test_admin_client_has_explicit_timeouts(tmp_path):
    executor, _ = _executor(tmp_path)
    timeout = executor._client.timeout
    assert timeout.read == 5.0
    assert timeout.connect == 2.0


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (httpx.ConnectError("refused"), "not applied"),
        (httpx.ReadTimeout("slow"), "may have been applied"),
    ],
)
def test_failed_execute_records_an_event_saying_whether_it_may_have_applied(
    tmp_path, monkeypatch, error, expected
):
    executor, store = _executor(tmp_path)

    def failing_post(url, json, headers=None):
        raise error

    monkeypatch.setattr(executor._client, "post", failing_post)

    with pytest.raises(RemediationError, match=expected):
        executor.execute("inc-1", "op")

    failed = [e for e in store.events("inc-1") if e["kind"] == "remediation_failed"]
    assert len(failed) == 1
    assert expected in failed[0]["message"]
    assert store.get_incident("inc-1")["status"] == "approved"


def test_server_rejection_is_recorded_as_not_applied(tmp_path, monkeypatch):
    executor, _ = _executor(tmp_path)

    class Rejected:
        def raise_for_status(self):
            request = httpx.Request("POST", "http://inventory/admin/faults/clear")
            raise httpx.HTTPStatusError(
                "forbidden", request=request, response=httpx.Response(403, request=request)
            )

    monkeypatch.setattr(executor._client, "post", lambda url, json, headers=None: Rejected())

    with pytest.raises(RemediationError, match="rejected, not applied"):
        executor.execute("inc-1", "op")


def test_a_malformed_url_is_a_remediation_error_not_a_crash(tmp_path, monkeypatch):
    executor, store = _executor(tmp_path)

    def bad_url(url, json, headers=None):
        raise httpx.InvalidURL("bad")

    monkeypatch.setattr(executor._client, "post", bad_url)

    with pytest.raises(RemediationError):
        executor.execute("inc-1", "op")
    assert store.get_incident("inc-1")["status"] == "approved"


def test_unreadable_success_body_still_counts_as_executed(tmp_path, monkeypatch):
    executor, store = _executor(tmp_path)
    monkeypatch.setattr(executor._client, "post", lambda url, json, headers=None: OkResponse())

    result = executor.execute("inc-1", "op")

    assert result["status"] == "executed"
    assert store.get_incident("inc-1")["status"] == "open"
    assert result["result"] == {"raw": "not json"}


def test_evidence_that_arrives_during_the_admin_call_survives(tmp_path, monkeypatch):
    executor, store = _executor(tmp_path)

    def slow_post(url, json, headers=None):
        store.upsert_incident("x", "t", "high", "dependency:inventory", {"n": 1})
        return OkResponse()

    monkeypatch.setattr(executor._client, "post", slow_post)
    executor.execute("inc-1", "op")

    data = store.get_incident("inc-1")["data"]
    assert [item["n"] for item in data["evidence"]] == [0, 1]
    assert data["remediation"]["approver"] == "op"
    assert data["approval"]["approver"] == "op"
