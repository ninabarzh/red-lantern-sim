# ROA poisoning / Control plane manipulation

## What this scenario represents

A sophisticated attacker compromises credentials to manipulate RPKI/ROA records and indirectly poison BGP routing.

## What is being simulated

- Initial access via compromised user accounts
- ROA deletion and manipulation
- Policy changes to enable malicious announcements
- Malicious BGP announcements validated via manipulated ROAs
- Route rejections and blackhole communities
- Coordinated route flapping to mask the attack
- Cleanup and ROA restoration

## Detections and signals exercised

- `access.login` and `access.logout` events showing unusual credentials and locations
- `router.syslog` warnings and critical messages for ROA removal, route rejection, and blackhole communities
- `bgp.update` events with attacker AS paths
- `rpki.validation` events reflecting manipulated validation states
- Detection of coordinated flapping patterns

## How to run

From the repository root:

```bash
python -m simulator.cli simulator/scenarios/advanced/roa_poisoning/scenario.yaml
```

