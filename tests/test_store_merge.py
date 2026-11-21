"""merge_incident is an atomic read-modify-write that never loses concurrent evidence."""

import threading

from aegis.storage import Store


def _store(tmp_path, max_evidence=1000):
    return Store(str(tmp_path / "db.sqlite"), max_evidence=max_evidence)


def test_merge_keeps_evidence_appended_after_the_caller_read_its_snapshot(tmp_path):
    store = _store(tmp_path)
    store.upsert_incident("inc-1", "t", "high", "service:x", {"n": 0})
    snapshot = store.get_incident("inc-1")  # what investigate/approve used to write back

    store.upsert_incident("inc-2", "t", "high", "service:x", {"n": 1})
    merged = store.merge_incident("inc-1", {"investigation": {"mode": "local"}}, status="recommendation_pending")

    assert snapshot is not None
    assert merged is not None
    assert merged["status"] == "recommendation_pending"
    assert merged["data"]["investigation"] == {"mode": "local"}
    assert [item["n"] for item in merged["data"]["evidence"]] == [0, 1]
    assert merged["data"]["latest_evidence"] == {"n": 1}


def test_merge_is_skipped_when_the_status_is_not_allowed(tmp_path):
    store = _store(tmp_path)
    store.upsert_incident("inc-1", "t", "high", "service:x", {"n": 0})

    result = store.merge_incident(
        "inc-1", {"approval": {}}, status="approved", only_if_status={"recommendation_pending"}
    )

    assert result is None
    incident = store.get_incident("inc-1")
    assert incident is not None
    assert incident["status"] == "open"
    assert "approval" not in incident["data"]


def test_merge_of_a_missing_incident_returns_none(tmp_path):
    assert _store(tmp_path).merge_incident("nope", {"a": 1}) is None


def test_merge_sets_resolved_at_and_leaves_status_alone_by_default(tmp_path):
    store = _store(tmp_path)
    store.upsert_incident("inc-1", "t", "high", "service:x", {"n": 0})

    merged = store.merge_incident("inc-1", resolved_at="2026-01-01T00:00:00+00:00")

    assert merged is not None
    assert merged["status"] == "open"
    assert merged["resolved_at"] == "2026-01-01T00:00:00+00:00"


def test_concurrent_merges_and_upserts_lose_nothing(tmp_path):
    store = _store(tmp_path)
    store.upsert_incident("inc-1", "t", "high", "service:x", {"n": 0})
    upserts = 150
    errors: list[BaseException] = []

    def upsert_worker():
        try:
            for index in range(1, upserts + 1):
                store.upsert_incident("ignored", "t", "high", "service:x", {"n": index})
        except BaseException as exc:  # surfaced by the assertion below
            errors.append(exc)

    def merge_worker(name):
        try:
            for index in range(upserts):
                store.merge_incident("inc-1", {name: index})
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=upsert_worker)] + [
        threading.Thread(target=merge_worker, args=(f"key{i}",)) for i in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    incident = store.get_incident("inc-1")
    assert incident is not None
    assert len(incident["data"]["evidence"]) == upserts + 1
    assert all(incident["data"][f"key{i}"] == upserts - 1 for i in range(3))
