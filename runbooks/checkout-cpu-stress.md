# Checkout CPU stress

## Signal

`aegis_cpu_burn_active{service="checkout"}` is active and checkout latency may rise as worker capacity is consumed.

## Safe response

Confirm the synthetic CPU gauge and the service logs. Propose clearing only the bounded `cpu` fault on checkout. Do not execute a host-level process kill or an unbounded scale operation.

