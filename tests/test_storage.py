from aegis.storage import Store


def test_same_root_cause_is_correlated_into_one_incident(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
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
