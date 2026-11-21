import pytest

from aegis.remediation import RemediationError, RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"status": "cleared"}


def test_validate_recommendation_rejects_unbounded_or_mismatched_actions(tmp_path):
    executor = RemediationExecutor(
        Settings(
            db_path=str(tmp_path / "db.sqlite"),
            checkout_url="http://checkout",
            inventory_url="http://inventory",
        ),
        Store(str(tmp_path / "db.sqlite")),
    )

    with pytest.raises(RemediationError, match=r"[Ff]ault is outside"):
        executor.validate_recommendation(
            {
                "action": "clear_fault",
                "target": "checkout",
                "parameters": {"fault": "shell"},
            }
        )
    with pytest.raises(RemediationError, match="valid for the selected target"):
        executor.validate_recommendation(
            {
                "action": "clear_fault",
                "target": "checkout",
                "parameters": {"fault": "dependency"},
            }
        )


def test_execute_uses_the_approved_recommendation_snapshot(tmp_path, monkeypatch):
    db_path = str(tmp_path / "db.sqlite")
    settings = Settings(
        db_path=db_path,
        checkout_url="http://checkout",
        inventory_url="http://inventory",
        api_key="test-key",
    )
    store = Store(db_path)
    incident, _ = store.upsert_incident(
        "inc-remediation",
        "inventory dependency",
        "high",
        "dependency:inventory",
        {"value": 1},
    )
    approved = {
        "action": "clear_fault",
        "target": "inventory",
        "parameters": {"fault": "dependency"},
    }
    data = {
        **incident["data"],
        "recommendation": {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "errors"},
        },
        "approval": {"approver": "operator", "recommendation": approved},
    }
    store.update_incident(incident["id"], status="approved", data=data)

    calls = []

    def fake_post(url, json, headers=None, timeout=None):
        calls.append((url, json, headers))
        return FakeResponse()

    executor = RemediationExecutor(settings, store)
    monkeypatch.setattr(executor._client, "post", fake_post)
    result = executor.execute(incident["id"], "operator")

    assert result["target"] == "inventory"
    assert calls == [
        (
            "http://inventory/admin/faults/clear",
            {"fault": "dependency"},
            {"Authorization": "Bearer test-key"},
        )
    ]


def test_execute_requires_admin_key(tmp_path):
    db_path = str(tmp_path / "db.sqlite")
    settings = Settings(
        db_path=db_path,
        checkout_url="http://checkout",
        inventory_url="http://inventory",
    )
    store = Store(db_path)
    incident, _ = store.upsert_incident(
        "inc-no-key", "inventory dependency", "high", "dependency:inventory", {"value": 1}
    )
    recommendation = {
        "action": "clear_fault",
        "target": "inventory",
        "parameters": {"fault": "dependency"},
    }
    store.update_incident(
        incident["id"],
        status="approved",
        data={"approval": {"recommendation": recommendation}},
    )
    executor = RemediationExecutor(settings, store)

    with pytest.raises(RemediationError, match="AEGIS_API_KEY"):
        executor.execute(incident["id"], "operator")


@pytest.mark.parametrize("bad", [["clear_fault"], {"a": 1}])
@pytest.mark.parametrize("field", ["action", "target"])
def test_validate_recommendation_rejects_unhashable_action_or_target(tmp_path, field, bad):
    executor = RemediationExecutor(
        Settings(
            db_path=str(tmp_path / "db.sqlite"),
            checkout_url="http://checkout",
            inventory_url="http://inventory",
        ),
        Store(str(tmp_path / "db.sqlite")),
    )
    recommendation = {
        "action": "clear_fault",
        "target": "checkout",
        "parameters": {"fault": "errors"},
        field: bad,
    }

    with pytest.raises(RemediationError, match="allowlist"):
        executor.validate_recommendation(recommendation)


def _approved_executor(tmp_path):
    db_path = str(tmp_path / "db.sqlite")
    settings = Settings(
        db_path=db_path,
        checkout_url="http://checkout",
        inventory_url="http://inventory",
        api_key="test-key",
    )
    store = Store(db_path)
    store.upsert_incident("inc-race", "t", "high", "dependency:inventory", {"value": 1})
    recommendation = {
        "action": "clear_fault",
        "target": "inventory",
        "parameters": {"fault": "dependency"},
    }
    store.update_incident(
        "inc-race", status="approved", data={"approval": {"recommendation": recommendation}}
    )
    return RemediationExecutor(settings, store), store


def test_concurrent_execute_fires_the_admin_action_once(tmp_path, monkeypatch):
    import threading

    executor, store = _approved_executor(tmp_path)
    calls = []
    in_flight = threading.Event()
    release = threading.Event()

    def slow_post(url, json, headers=None, timeout=None):
        calls.append(url)
        in_flight.set()
        release.wait(timeout=5)
        return FakeResponse()

    monkeypatch.setattr(executor._client, "post", slow_post)
    outcomes: list[object] = []

    def run():
        try:
            outcomes.append(executor.execute("inc-race", "operator"))
        except RemediationError as exc:
            outcomes.append(exc)

    first = threading.Thread(target=run)
    first.start()
    assert in_flight.wait(timeout=5)
    second = threading.Thread(target=run)
    second.start()
    second.join(timeout=5)
    release.set()
    first.join(timeout=5)

    assert len(calls) == 1
    assert sorted(type(o).__name__ for o in outcomes) == ["RemediationError", "dict"]
    assert store.get_incident("inc-race")["status"] == "open"


def test_failed_execute_returns_incident_to_approved_for_retry(tmp_path, monkeypatch):
    import httpx

    executor, store = _approved_executor(tmp_path)

    def failing_post(url, json, headers=None, timeout=None):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(executor._client, "post", failing_post)

    with pytest.raises(RemediationError, match="request failed"):
        executor.execute("inc-race", "operator")

    assert store.get_incident("inc-race")["status"] == "approved"
