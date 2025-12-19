# Fat Finger Hijack

## What this scenario represents

A classic human mistake in BGP configuration: an operator accidentally announces someone else’s prefix as their own.

## What is being simulated

- Mis-origin BGP announcements
- Route propagation to peers
- Automated prefix limit alerts
- Quick withdrawal once the mistake is noticed
- Minimal impact, short-lived route hijack

## Detections and signals exercised

- `bgp.update` events with unusual origin AS
- Router syslogs showing route addition and withdrawal
- Prefix-limit warnings (`router.syslog` severity `error`)
- Timing correlation: short duration anomalies

## How to run

From the repository root:

```bash
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml
```




