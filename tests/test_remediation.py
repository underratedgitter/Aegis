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

    with pytest.raises(RemediationError, match="[Ff]ault is outside"):
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
        db_path=db_path, checkout_url="http://checkout", inventory_url="http://inventory"
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

    def fake_post(url, json, timeout=None):
        calls.append((url, json))
        return FakeResponse()

    executor = RemediationExecutor(settings, store)
    monkeypatch.setattr(executor._client, "post", fake_post)
    result = executor.execute(incident["id"], "operator")

    assert result["target"] == "inventory"
    assert calls == [("http://inventory/admin/faults/clear", {"fault": "dependency"})]
