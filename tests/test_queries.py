"""The alert and SLO queries must measure API traffic, not scrapes and probes."""

import json
from pathlib import Path

import pytest

from aegis.queries import (
    CHECKOUT_ERROR_RATE,
    CHECKOUT_ERRORS_30M,
    CHECKOUT_P95_LATENCY,
    CHECKOUT_REQUESTS_30M,
)

DASHBOARD = Path(__file__).resolve().parent.parent / "observability/grafana/dashboards/aegis.json"
HTTP_QUERIES = [CHECKOUT_ERROR_RATE, CHECKOUT_P95_LATENCY, CHECKOUT_REQUESTS_30M, CHECKOUT_ERRORS_30M]


@pytest.mark.parametrize("query", HTTP_QUERIES)
def test_http_queries_count_only_api_routes(query):
    # /metrics and /healthz are hit every few seconds; they must not dilute the error rate or p95.
    assert 'route=~"/api/.*"' in query


def test_dashboard_panels_use_the_alert_queries():
    panels = json.loads(DASHBOARD.read_text())["panels"]
    expressions = {target["expr"] for panel in panels for target in panel.get("targets", [])}

    assert {CHECKOUT_ERROR_RATE, CHECKOUT_P95_LATENCY} <= expressions
