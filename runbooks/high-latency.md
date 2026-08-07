# High latency

## Signal

Checkout p95 request latency is above 750ms.

## Triage

Inspect the dependency latency histogram and recent logs. High latency with inventory dependency failures should be correlated into the inventory dependency incident; latency without an upstream signal remains a checkout investigation.

