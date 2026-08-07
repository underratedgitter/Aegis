# Checkout high error rate

## Signal

The checkout 5xx ratio is above 15% for the two-minute Prometheus window.

## Triage

Compare `aegis_http_requests_total` by status with dependency errors, inspect recent JSON logs, and check whether a chaos fault is active. If inventory dependency failures are present, correlate this alert into the inventory incident.

## Safe response

If the evidence points to the demo's injected checkout error fault, propose clearing only the `errors` fault on checkout. This is a bounded action and still requires human approval.

