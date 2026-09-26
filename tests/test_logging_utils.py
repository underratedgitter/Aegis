"""Tests for the JSON logging utilities."""

import json
import logging

from aegis.logging_utils import JsonFormatter, configure_logging


class TestJsonFormatter:
    def test_format_includes_core_fields(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="aegis.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        payload = json.loads(formatter.format(record))
        assert payload["level"] == "info"
        assert payload["message"] == "hello world"
        assert payload["service"] == "aegis"
        assert "host" in payload
        assert "ts" in payload

    def test_format_uses_service_attribute_when_present(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="aegis.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="degraded",
            args=(),
            exc_info=None,
        )
        record.service = "checkout"
        payload = json.loads(formatter.format(record))
        assert payload["service"] == "checkout"

    def test_format_includes_optional_context_fields(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="aegis.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="request failed",
            args=(),
            exc_info=None,
        )
        record.request_id = "req-1"
        record.route = "/api/incidents"
        record.status = 500
        record.duration_ms = 12.5
        record.fault = "timeout"
        record.dependency = "inventory"
        payload = json.loads(formatter.format(record))
        assert payload["request_id"] == "req-1"
        assert payload["route"] == "/api/incidents"
        assert payload["status"] == 500
        assert payload["duration_ms"] == 12.5
        assert payload["fault"] == "timeout"
        assert payload["dependency"] == "inventory"

    def test_format_omits_optional_fields_when_absent(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="aegis.test",
            level=logging.DEBUG,
            pathname=__file__,
            lineno=1,
            msg="quiet",
            args=(),
            exc_info=None,
        )
        payload = json.loads(formatter.format(record))
        for key in ("request_id", "route", "status", "duration_ms", "fault", "dependency"):
            assert key not in payload


class TestConfigureLogging:
    def test_returns_logger_with_stream_handler(self):
        logger = configure_logging("aegis-test-stream")
        assert logger.name == "aegis-test-stream"
        assert logger.level == logging.INFO
        assert logger.propagate is False
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert isinstance(logger.handlers[0].formatter, JsonFormatter)

    def test_adds_file_handler_when_log_path_given(self, tmp_path):
        log_path = tmp_path / "nested" / "aegis.log"
        logger = configure_logging("aegis-test-file", log_path=str(log_path))
        try:
            assert len(logger.handlers) == 2
            assert any(isinstance(h, logging.FileHandler) for h in logger.handlers)
            assert log_path.parent.is_dir()
        finally:
            for handler in logger.handlers:
                handler.close()

    def test_reconfiguring_clears_previous_handlers(self):
        logger = configure_logging("aegis-test-reconfigure")
        first_handler_count = len(logger.handlers)
        logger = configure_logging("aegis-test-reconfigure")
        assert len(logger.handlers) == first_handler_count
