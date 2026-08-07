# Inventory dependency failure

## Signal

Checkout returns 502/504 responses and `aegis_dependency_errors_total{dependency="inventory"}` is rising. A correlated checkout error-rate or latency alert is part of the same incident.

## Likely causes

- The inventory service is returning 5xx responses.
- The inventory service has synthetic latency or a dependency fault injected.
- A network boundary between checkout and inventory is unhealthy.

## Safe response

1. Confirm the dependency error rate and recent structured logs.
2. Check the inventory service health endpoint.
3. For this demo, propose clearing the bounded `dependency` fault on inventory.
4. Require a human approval before executing the clear-fault action.
5. Confirm two healthy polling cycles and record the resolution time.

## Do not

Do not restart arbitrary containers, run shell commands, or broaden the remediation target without an operator decision.

