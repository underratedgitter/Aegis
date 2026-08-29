"""Tests for telemetry module."""

import json
from unittest.mock import MagicMock, patch

from aegis.settings import Settings
from aegis.telemetry import Telemetry


class TestTelemetry:
    def setup_method(self):
        self.settings = Settings(
            prometheus_url="http://localhost:9090",
            loki_url="http://localhost:3100",
            log_dir="./logs",
        )

    def teardown_method(self):
        # Clean up any created client
        pass

    def test_prometheus_query_success(self):
        telemetry = Telemetry(self.settings)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"value": [1234567890, "1.5"]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(telemetry._client, "get", return_value=mock_response):
            result = telemetry.prometheus_query("up")
            assert result["value"] == 1.5
            assert result["source"] == "prometheus"

    def test_prometheus_query_empty_result(self):
        telemetry = Telemetry(self.settings)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": []},
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(telemetry._client, "get", return_value=mock_response):
            result = telemetry.prometheus_query("up")
            assert result["value"] is None

    def test_prometheus_query_failure(self):
        telemetry = Telemetry(self.settings)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "error",
            "error": "query failed",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(telemetry._client, "get", return_value=mock_response):
            result = telemetry.prometheus_query("invalid_query")
            assert result["value"] is None
            assert "error" in result

    def test_prometheus_query_http_error(self):
        telemetry = Telemetry(self.settings)
        import httpx
        with patch.object(telemetry._client, "get", side_effect=httpx.HTTPError("Connection failed")):
            result = telemetry.prometheus_query("up")
            assert result["value"] is None
            assert "error" in result

    def test_recent_logs_reads_jsonl(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.jsonl"

        logs = [
            json.dumps({"service": "test", "ts": "2024-01-01T00:00:00", "message": "log1"}),
            json.dumps({"service": "test", "ts": "2024-01-01T00:00:01", "message": "log2"}),
            json.dumps({"service": "other", "ts": "2024-01-01T00:00:02", "message": "log3"}),
        ]
        log_file.write_text("\n".join(logs))

        settings = Settings(log_dir=str(log_dir))
        telemetry = Telemetry(settings)

        result = telemetry.recent_logs(service="test", limit=10)
        assert len(result) == 2
        assert all(log["service"] == "test" for log in result)

    def test_recent_logs_with_limit(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.jsonl"

        logs = [
            json.dumps({"service": "test", "ts": f"2024-01-01T00:00:{i:02d}", "message": f"log{i}"})
            for i in range(20)
        ]
        log_file.write_text("\n".join(logs))

        settings = Settings(log_dir=str(log_dir))
        telemetry = Telemetry(settings)

        result = telemetry.recent_logs(service="test", limit=5)
        assert len(result) == 5

    def test_recent_logs_handles_missing_file(self, tmp_path):
        settings = Settings(log_dir=str(tmp_path / "nonexistent"))
        telemetry = Telemetry(settings)

        result = telemetry.recent_logs()
        assert result == []

    def test_loki_status_available(self):
        telemetry = Telemetry(self.settings)
        mock_response = MagicMock()
        mock_response.is_success = True
        mock_response.status_code = 200

        with patch.object(telemetry._client, "get", return_value=mock_response):
            status = telemetry.loki_status()
            assert status.available is True

    def test_loki_status_unavailable(self):
        telemetry = Telemetry(self.settings)
        import httpx
        with patch.object(telemetry._client, "get", side_effect=httpx.HTTPError("Connection refused")):
            status = telemetry.loki_status()
            assert status.available is False
            assert "error" in status.model_dump()

    def test_slo_snapshot_no_traffic(self):
        telemetry = Telemetry(self.settings)
        with patch.object(telemetry, "prometheus_query", return_value={"value": None}):
            slo = telemetry.slo_snapshot()
            assert slo.actual is None
            assert slo.error_budget_remaining is None

    def test_slo_snapshot_with_traffic(self):
        telemetry = Telemetry(self.settings)

        def mock_query(query):
            if "status=~" in query:
                return {"value": 5.0}
            return {"value": 1000.0}

        with patch.object(telemetry, "prometheus_query", side_effect=mock_query):
            slo = telemetry.slo_snapshot()
            assert slo.actual is not None
            assert 0.99 <= slo.actual <= 1.0
            assert slo.error_budget_remaining is not None
