"""
Canonical PromQL used by Aegis.

The alert rules and the metric snapshot previously carried their own copies of
these strings. Keeping one definition means a query can be corrected in a single
place instead of drifting between detection and display.
"""

from __future__ import annotations

from typing import Final

CHECKOUT_ERROR_RATE: Final = (
    'sum(rate(aegis_http_requests_total{service="checkout",status=~"5.."}[2m])) '
    '/ clamp_min(sum(rate(aegis_http_requests_total{service="checkout"}[2m])), 0.001)'
)

CHECKOUT_P95_LATENCY: Final = (
    "histogram_quantile(0.95, sum(rate(aegis_http_request_duration_seconds_bucket"
    '{service="checkout"}[2m])) by (le))'
)

INVENTORY_DEPENDENCY_ERRORS: Final = (
    'sum(rate(aegis_dependency_errors_total{service="checkout",dependency="inventory"}[2m]))'
)

CHECKOUT_CPU_BURN: Final = 'aegis_cpu_burn_active{service="checkout"}'

CHECKOUT_REQUESTS_30M: Final = (
    'sum(increase(aegis_http_requests_total{service="checkout"}[30m]))'
)

CHECKOUT_ERRORS_30M: Final = (
    'sum(increase(aegis_http_requests_total{service="checkout",status=~"5.."}[30m]))'
)

# Above this rate, checkout symptoms are attributed to the inventory dependency
# rather than to checkout itself.
DEPENDENCY_ERROR_THRESHOLD: Final = 0.05

SNAPSHOT_QUERIES: Final[dict[str, str]] = {
    "checkout_error_rate": CHECKOUT_ERROR_RATE,
    "checkout_p95_latency": CHECKOUT_P95_LATENCY,
    "inventory_dependency_errors": INVENTORY_DEPENDENCY_ERRORS,
    "checkout_cpu_burn": CHECKOUT_CPU_BURN,
}
