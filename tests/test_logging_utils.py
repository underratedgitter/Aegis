"""Tests for the JSON logging utilities."""

import json
import logging
import logging.handlers
import sys

import pytest

from aegis.logging_utils import JsonFormatter, configure_logging


@pytest.fixture
def restore_aegis_logger():
    """configure_logging sets up the shared "aegis" logger; put it back after the test."""
    logger = logging.getLogger("aegis")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    yield logger
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]


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

    def test_format_strips_credentials_from_urls_in_the_message(self):
        record = logging.LogRecord(
            name="aegis.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="query to %s failed",
            args=("http://admin:hunter2@prometheus:9090/api",),
            exc_info=None,
        )
        payload = json.loads(JsonFormatter().format(record))
        assert payload["message"] == "query to http://prometheus:9090/api failed"

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


class TestExceptions:
    def test_format_includes_the_exception_text_without_url_credentials(self):
        try:
            raise ValueError("cannot reach http://admin:hunter2@prometheus:9090")
        except ValueError:
            record = logging.LogRecord(
                name="aegis.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="query failed",
                args=(),
                exc_info=sys.exc_info(),
            )
        payload = json.loads(JsonFormatter().format(record))
        assert "ValueError: cannot reach http://prometheus:9090" in payload["exception"]
        assert "hunter2" not in payload["exception"]
        assert "Traceback" in payload["exception"]

    def test_format_omits_the_exception_field_when_there_is_none(self):
        record = logging.LogRecord("aegis.test", logging.INFO, __file__, 1, "fine", (), None)
        assert "exception" not in json.loads(JsonFormatter().format(record))

    def test_default_service_comes_from_the_formatter(self):
        record = logging.LogRecord("aegis.test", logging.INFO, __file__, 1, "hi", (), None)
        assert json.loads(JsonFormatter("checkout").format(record))["service"] == "checkout"


class TestModuleLoggers:
    """incidents, supervisor, remediation and agent log through aegis.<module> loggers."""

    def test_module_loggers_write_json_info_records_with_the_configured_service(
        self, tmp_path, restore_aegis_logger
    ):
        log_path = tmp_path / "control.jsonl"
        configure_logging("aegis-control-plane", log_path=str(log_path))

        logging.getLogger("aegis.incidents").info("incident opened")
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logging.getLogger("aegis.supervisor").exception("cycle failed")

        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        assert [(line["level"], line["message"], line["service"]) for line in lines] == [
            ("info", "incident opened", "aegis-control-plane"),
            ("error", "cycle failed", "aegis-control-plane"),
        ]
        assert "RuntimeError: boom" in lines[1]["exception"]

    def test_module_loggers_share_the_configured_handlers(self, restore_aegis_logger):
        logger = configure_logging("aegis-test-single")
        assert logging.getLogger("aegis").handlers == logger.handlers

    def test_a_record_can_still_override_the_service(self, tmp_path, restore_aegis_logger):
        log_path = tmp_path / "svc.jsonl"
        logger = configure_logging("checkout", log_path=str(log_path))

        logger.info("request_completed", extra={"service": "inventory"})
        logging.getLogger("aegis.auth").info("from a module")

        services = [json.loads(line)["service"] for line in log_path.read_text().splitlines()]
        assert services == ["inventory", "checkout"]


class TestConfigureLogging:
    def test_service_logs_rotate(self, tmp_path, restore_aegis_logger):
        logger = configure_logging("aegis-test-rotate", log_path=str(tmp_path / "svc.jsonl"))
        rotating = [h for h in logger.handlers if isinstance(h, logging.handlers.RotatingFileHandler)]

        assert len(rotating) == 1
        assert rotating[0].maxBytes > 0
        assert rotating[0].backupCount > 0

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
