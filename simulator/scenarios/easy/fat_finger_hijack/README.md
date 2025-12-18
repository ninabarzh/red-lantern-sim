# Fat-finger hijack

## What this scenario models

A common, low-sophistication BGP incident where a legitimate AS accidentally announces the exact prefix of another AS.

- No interception.
- No nation-state.
- No cleverness.

Just entropy and missing controls.

This happens multiple times per year on the real Internet.

## Threat model reality

Attacker capability:

- Legitimate AS with upstream connectivity
- No RPKI enforcement by peers
- Prefix filters missing or outdated

Defensive posture:

- Relies on upstream filtering
- Monitoring is reactive
- Detection often comes from social media

## Attack chain

1. Attacker already peers with one or more transit providers
2. Exact-prefix announcement is made (looks like a mistake)
3. Some upstreams accept the route
4. Traffic is blackholed or partially rerouted
5. Route is withdrawn after a short period

Plausible deniability achieved.

## What telemetry is generated

This scenario produces mocked but realistic signals:

- BGP UPDATE with unexpected origin AS
- Short-lived route visibility
- Router syslog messages indicating control-plane churn

These signals are suitable for:
- Wazuh ingestion
- SOC detection exercises
- Purple-team walkthroughs

## How to run

From the repository root:

```bash
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml
```

You should see:

- Scenario events (timeline)
- Derived BGP telemetry
- Router syslog messages

All tagged with scenario name and attack step.



