"""Incident listing, export, overview and the engine read the whole table, not a truncated slice."""

import json

import pytest
from fastapi.testclient import TestClient

from aegis.control_plane import app, store
from aegis.incidents import IncidentEngine
from aegis.settings import Settings
from aegis.storage import Store

ROOT = "bulkq:"


def insert_incidents(target, count, *, status="resolved", prefix=ROOT, severity="medium", data=None):
    """Bulk-insert rows directly; going through upsert_incident would take minutes."""
    rows = [
        (
            f"{prefix}{n:05d}",
            f"Bulk incident {n}",
            severity,
            status,
            f"{prefix}{n:05d}",
            f"2026-01-01T00:{n // 60 % 60:02d}:{n % 60:02d}+00:00",
            f"2026-01-01T00:{n // 60 % 60:02d}:{n % 60:02d}+00:00",
            json.dumps(data or {"evidence": [{"value": n}] * 5, "latest_evidence": {"value": n}}),
        )
        for n in range(count)
    ]
    target.db.executemany(
        "INSERT INTO incidents(id,title,severity,status,root_cause_key,first_seen,last_seen,data_json)"
        " VALUES(?,?,?,?,?,?,?,?)",
        rows,
    )
    target.db.commit()


@pytest.fixture
def local(tmp_path):
    local_store = Store(str(tmp_path / "aegis.db"))
    yield local_store
    local_store.close()


@pytest.fixture
def shared():
    """Rows added to the control plane's shared store are removed again."""
    yield store
    store.db.execute("DELETE FROM incidents WHERE id LIKE 'bulkq:%'")
    store.db.commit()


@pytest.fixture
def client():
    return TestClient(app)


class TestQueryIncidents:
    def test_totals_and_pages_cover_every_row_not_just_the_first_500(self, local):
        insert_incidents(local, 650)

        page, total = local.query_incidents(offset=600, limit=100)

        assert total == 650
        assert len(page) == 50

    def test_filters_are_applied_in_sql_before_paging(self, local):
        insert_incidents(local, 40, status="resolved", severity="high", prefix="old:")
        insert_incidents(local, 700, status="open", severity="medium", prefix="new:")

        rows, total = local.query_incidents(status="resolved", severity="high", limit=10)

        assert total == 40
        assert {r["status"] for r in rows} == {"resolved"}
        assert local.query_incidents(severity="low")[1] == 0
        assert local.query_incidents(status="open", limit=1)[1] == 700

    def test_search_is_case_insensitive_literal_and_matches_title_or_root_cause(self, local):
        local.upsert_incident("inc-1", "Checkout Latency", "high", "service:checkout", {})
        local.upsert_incident("inc-2", "Disk full", "high", "node:100%_full", {})

        assert [r["id"] for r in local.query_incidents(search="LATENCY")[0]] == ["inc-1"]
        assert [r["id"] for r in local.query_incidents(search="service:check")[0]] == ["inc-1"]
        assert [r["id"] for r in local.query_incidents(search="100%_")[0]] == ["inc-2"]
        assert local.query_incidents(search="%")[1] == 1
        assert local.query_incidents(search="nothing")[1] == 0

    def test_active_incidents_come_before_resolved_ones(self, local):
        insert_incidents(local, 5, status="resolved", prefix="r:")
        insert_incidents(local, 3, status="open", prefix="o:")

        rows, _ = local.query_incidents(limit=4)

        assert [r["status"] for r in rows] == ["open", "open", "open", "resolved"]

    def test_rows_are_summaries_without_the_evidence_history(self, local):
        data = {
            "evidence": [{"value": 1}] * 50,
            "latest_evidence": {"value": 1},
            "remediation": {"verification": {"state": "verified"}, "result": {"big": "x" * 500}},
            "investigation": {
                "hypothesis": "h",
                "evidence": [
                    {"source": "runbook", "label": "checkout-latency", "detail": "long text"},
                    {"source": "metrics", "label": "p95", "detail": "more"},
                ],
            },
        }
        insert_incidents(local, 1, data=data)

        [row], _ = local.query_incidents()

        assert row["data"] == {
            "remediation": {"verification": {"state": "verified"}},
            "investigation": {"evidence": [{"source": "runbook", "label": "checkout-latency"}]},
        }
        assert row["title"] == "Bulk incident 0"
        assert "data_json" not in row

    def test_an_incident_without_investigation_has_an_empty_summary(self, local):
        insert_incidents(local, 1)

        assert local.query_incidents()[0][0]["data"] == {}

    def test_the_status_index_exists(self, local):
        names = {r[1] for r in local.db.execute("PRAGMA index_list('incidents')")}
        assert "incidents_status_last_seen_idx" in names


class TestExportAndActive:
    def test_iter_incidents_yields_every_row_with_full_data(self, local):
        insert_incidents(local, 1234)

        rows = list(local.iter_incidents(batch_size=100))

        assert len(rows) == 1234
        assert len({r["id"] for r in rows}) == 1234
        assert all(len(r["data"]["evidence"]) == 5 for r in rows)

    def test_active_incidents_is_not_capped_and_excludes_finished_ones(self, local):
        insert_incidents(local, 120, status="open", prefix="a:")
        insert_incidents(local, 10, status="resolved", prefix="b:")
        insert_incidents(local, 5, status="closed", prefix="c:")

        active = local.active_incidents()

        assert len(active) == 120
        assert {r["status"] for r in active} == {"open"}

    def test_incident_counts_are_computed_over_the_whole_table(self, local):
        insert_incidents(local, 30, status="open", prefix="a:", data={"investigation": {"x": 1}})
        insert_incidents(local, 70, status="resolved", prefix="b:", data={})

        assert local.investigated_count() == 30


class TestApi:
    def test_list_pages_filter_and_count_in_sql(self, client, shared):
        insert_incidents(shared, 600)

        body = client.get("/api/incidents", params={"search": ROOT, "page": 3, "limit": 200}).json()

        assert body["pagination"] == {"page": 3, "limit": 200, "total": 600, "pages": 3}
        assert len(body["incidents"]) == 200
        assert "evidence" not in json.dumps(body["incidents"][0])

    def test_list_keeps_what_the_ui_needs(self, client, shared):
        data = {
            "investigation": {"evidence": [{"source": "runbook", "label": "rb"}]},
            "remediation": {"verification": {"state": "failed"}},
        }
        insert_incidents(shared, 1, prefix="bulkq:v", data=data)

        [row] = client.get("/api/incidents", params={"search": "bulkq:v"}).json()["incidents"]

        assert {"id", "title", "severity", "status", "root_cause_key", "last_seen"} <= set(row)
        assert row["data"]["remediation"]["verification"]["state"] == "failed"
        assert row["data"]["investigation"]["evidence"] == [{"source": "runbook", "label": "rb"}]

    def test_json_export_streams_every_incident_beyond_the_old_1000_cap(self, client, shared):
        insert_incidents(shared, 1200)

        body = client.get("/api/incidents/export?format=json").json()

        ids = {i["id"] for i in body["incidents"]}
        assert {f"{ROOT}{n:05d}" for n in range(1200)} <= ids
        assert body["count"] == len(body["incidents"])
        assert body["exported_at"]
        assert "evidence" in body["incidents"][0]["data"] or body["incidents"][0]["data"] == {}

    def test_csv_export_streams_every_incident_beyond_the_old_1000_cap(self, client, shared):
        insert_incidents(shared, 1200)

        response = client.get("/api/incidents/export?format=csv")

        lines = response.text.splitlines()
        assert lines[0].startswith("id,title,severity,status")
        assert sum(line.startswith(ROOT) for line in lines) == 1200
        assert "attachment" in response.headers["content-disposition"]

    def test_overview_counts_come_from_the_whole_table(self, client, shared):
        before = client.get("/api/overview").json()
        counts = store.incident_status_counts()
        insert_incidents(shared, 80, status="open", data={"investigation": {"x": 1}})

        after = client.get("/api/overview").json()

        assert after["open_incidents"] == before["open_incidents"] + 80
        total = sum(counts.values()) + 80
        investigated = store.investigated_count()
        assert after["agent_assisted_rate"] == round(investigated / total, 2)
        assert len(after["incidents"]) == 12


class TestEngineSeesEveryActiveIncident:
    def test_more_than_fifty_quiet_incidents_all_resolve(self, tmp_path):
        settings = Settings(
            db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", resolution_cycles=2
        )
        local_store = Store(settings.db_path)
        insert_incidents(local_store, 80, status="open", prefix="q:")
        engine = IncidentEngine(settings, local_store, telemetry=None)  # type: ignore[arg-type]

        engine._resolve_missing(set())
        engine._resolve_missing(set())

        assert local_store.incident_status_counts() == {"resolved": 80}
        local_store.close()
