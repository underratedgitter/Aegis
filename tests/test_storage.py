from aegis.storage import Store


def test_same_root_cause_is_correlated_into_one_incident(tmp_path):
    # Interval 0 records an event for every update; throttling is covered in test_signal_events.py.
    store = Store(str(tmp_path / "aegis.db"), signal_event_interval=0)
    first, created = store.upsert_incident(
        "inc-a", "errors", "high", "dependency:inventory", {"value": 1}
    )
    second, created_again = store.upsert_incident(
        "inc-b", "latency", "medium", "dependency:inventory", {"value": 2}
    )
    assert created is True
    assert created_again is False
    assert first["id"] == second["id"] == "inc-a"
    assert len(store.events("inc-a")) == 2
    assert len(second["data"]["evidence"]) == 2
    assert second["data"]["latest_evidence"] == {"value": 2}
