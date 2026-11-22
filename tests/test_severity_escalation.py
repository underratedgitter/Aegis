"""An active incident takes the highest severity any of its rules has reached."""

from aegis.storage import Store

ROOT = "service:checkout"


def store_with_latency_incident(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), signal_event_interval=0)
    store.upsert_incident(
        "inc-1", "Checkout p95 latency is elevated", "medium", ROOT, {"rule": "checkout_p95_latency"}
    )
    return store


def test_a_higher_severity_rule_on_the_same_root_raises_severity_and_title(tmp_path):
    store = store_with_latency_incident(tmp_path)

    incident, created = store.upsert_incident(
        "inc-2", "Checkout is not answering metric scrapes", "high", ROOT, {"rule": "checkout_down"}
    )

    assert created is False
    assert incident["id"] == "inc-1"
    assert incident["severity"] == "high"
    assert incident["title"] == "Checkout is not answering metric scrapes"
    raised = [e for e in store.events("inc-1") if e["kind"] == "severity_raised"]
    assert len(raised) == 1
    assert "medium" in raised[0]["message"]
    assert "high" in raised[0]["message"]
    assert raised[0]["data"]["rule"] == "checkout_down"
    store.close()


def test_a_lower_or_equal_severity_changes_nothing(tmp_path):
    store = store_with_latency_incident(tmp_path)
    store.upsert_incident("inc-2", "down", "high", ROOT, {"rule": "checkout_down"})

    incident, _ = store.upsert_incident("inc-3", "slow", "medium", ROOT, {"rule": "checkout_p95_latency"})
    again, _ = store.upsert_incident("inc-4", "down again", "high", ROOT, {"rule": "checkout_down"})

    assert incident["severity"] == again["severity"] == "high"
    assert incident["title"] == again["title"] == "down"
    assert len([e for e in store.events("inc-1") if e["kind"] == "severity_raised"]) == 1
    store.close()


def test_an_escalation_to_critical_is_not_undone_by_a_later_high_signal(tmp_path):
    store = store_with_latency_incident(tmp_path)
    store.update_incident("inc-1", severity="critical")

    incident, _ = store.upsert_incident("inc-2", "down", "high", ROOT, {"rule": "checkout_down"})

    assert incident["severity"] == "critical"
    assert incident["title"] == "Checkout p95 latency is elevated"
    store.close()
