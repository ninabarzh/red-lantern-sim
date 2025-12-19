# Subprefix interception

## What this scenario represents

An attacker announces a more specific subprefix to hijack traffic without disrupting the entire parent prefix.

## What is being simulated

- Normal baseline routing
- Subprefix announcement and propagation
- Traffic rerouting through the attacker’s AS
- Increased latency and minor packet anomalies
- Maintenance of interception before withdrawal

## Detections and signals exercised

- `bgp.update` events showing new subprefix AS paths
- Router syslogs indicating best-path changes and learned routes
- Latency anomalies and warnings (`latency.metrics`, `router.syslog` severity `warning`)
- Withdrawal events returning traffic to normal

## How to run

From the repository root:

```bash
python -m simulator.cli simulator/scenarios/medium/subprefix_intercept/scenario.yaml
```
