# Red Lantern simulator

![Version](https://img.shields.io/badge/status-active%20development-orange)
![Python](https://img.shields.io/badge/python-3.12+-blue)
![License](https://img.shields.io/badge/license-CC0-lightgrey)
![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)

Red Lantern Simulator is a deterministic attack-telemetry generator for network and routing security scenarios.

It simulates BGP and control-plane attack chains and emits structured JSON events designed to be ingested by Wazuh 
for detection engineering, rule testing, and analyst training.

* Attack realism without packet capture
* Timelines you can replay
* Optional background “Internet noise” for analyst realism
* Explicitly built for blue, purple, and red-team collaboration

The simulator functions within a classic cycle of attack and defence under the Patrician's shrewd management:

- The Spark (foreign element): The Scarlet Semaphore begins its "experimentation," visible only by [a fleeting internal notice](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/wall/internal-notice-tss) and red lanterns rearranging routes.
- The Reaction: The Department of Silent Stability detects the anomalies and [issues a cautious briefing](https://blue.tymyrddin.dev/docs/shadows/red-lantern/kickoff/internal-briefing-doss), which is promptly [intercepted by the attackers](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/wall/internal-briefing-doss).
- The Escalation: The red team uses this intelligence to [refine its "control-plane attack" theories](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/wall/control-plane), creating a formal catalog.
- The Patrician's Move: Seeing the activity as a useful but disruptive threat, the Patrician intervenes. He [recruits the talent](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/wall/ponders-visit), converting the threat into a strategic asset.
- The New Equilibrium: The project is rebranded under [Purple Lantern Practice Ltd.](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/spark/patrician-engagement), with the goal of "controlled burns" to strengthen the city's overall defenses, as the blue team continues its intelligence gathering and detection capabilities.

## Getting started (quick start)

Minimum viable run:

```bash
git clone https://github.com/ninabarzh/red-lantern-sim.git
cd red-lantern-sim
pip install -r requirements.txt
```

Run a scenario, for example:

```bash
python -m simulator.cli \
  simulator/scenarios/easy/fat_finger_hijack/scenario.yaml
```

See some [output examples](examples).

If you want Wazuh integration, read [wazuh/README.md](wazuh/README.md) before doing anything clever.

## Usage

### Basic run

```bash
python -m simulator.cli path/to/scenario.yaml
```

### --help

```
usage: simulator.cli [-h] [--mode {practice,training}] [--output {cli,json}]
                     [--json-file JSON_FILE] [--background]
                     [--bgp-noise-rate BGP_NOISE_RATE]
                     [--cmdb-noise-rate CMDB_NOISE_RATE]
                     scenario

Run a Red Lantern BGP attack-chain scenario

positional arguments:
  scenario                Path to the scenario YAML file

optional arguments:
  -h, --help              Show this help message and exit
  --mode {practice,training}
                          Select mode: 'practice' for realistic logs, 'training'
                          adds extra training lines (SCENARIO: debug lines)
                          (default: practice)
  --output {cli,json}     Output mode: 'cli' prints lines to stdout;
                          'json' dumps transformed events to a JSON file
                          (default: cli)
  --json-file JSON_FILE   Path to JSON output file if --output=json
                          (default: scenario_output.json)
  --background            Enable background noise feeds (BGP churn, CMDB
                          changes)
  --bgp-noise-rate BGP_NOISE_RATE
                          BGP updates per second (default: 0.5)
  --cmdb-noise-rate CMDB_NOISE_RATE
                          CMDB changes per second (default: 0.1)
```

Background events are tagged separately so analysts can distinguish signal from noise.

## Configuration

### Scenarios

Scenarios live under: [simulator/scenarios/](simulator/scenarios). Each scenario consists of:

* `scenario.yaml` — the timeline and intent
* `telemetry.py` — how events are generated
* `README.md` — attack description and assumptions

At minimum, a scenario YAML defines a timeline:

```yaml
id: fat_finger_hijack
timeline:
  - t: 0
    action: announce_prefix
  - t: 30
    action: withdraw_prefix
```

The simulator is *agnostic* about attack meaning. Semantics live in telemetry generators.

### Background traffic

[Background noise](simulator/feeds) is enabled via CLI (`--background`), not via scenario YAML. This is intentional: 
scenarios remain reusable.

## Extending the simulator

Red Lantern is designed to be easily changed/extended.

### Add a new scenario

Create a new folder under:

```
simulator/scenarios/{easy,medium,advanced}/your_scenario/
```

Each scenario folder contains its own README explaining:

* attacker intent
* prerequisites
* expected detections

### Add a new feed

Feeds live under: [simulator/feeds/](simulator/feeds):

* [bgp/](simulator/feeds/bgp): routing-level feeds
* [change_mgmt/](simulator/feeds/change_mgmt): CMDB and config context

Feeds may:

* provide baseline context
* generate background events
* enrich scenario telemetry

### Add a new output adapter

Adapters live under [simulator/output/](simulator/output/). Adapters format internal events:

* router syslog
* RPKI logs
* TACACS events
* ...
* Wazuh-ready JSON

## Installation details

### Requirements

* Python 3.12 or newer
* Linux or macOS recommended
* Windows might work but is not the priority target

### Common issues

* **“Module not found”**: Ensure you are running from the repository root.
* **Wazuh rules not firing**: Check decoder ordering and rule IDs. See `wazuh/README.md`.
* **Background noise too loud**: This is intentional. Set it to less loud.

## Architecture (high-level)

```
Scenario YAML
     |
ScenarioRunner ── SimulationClock
     |
  EventBus  <── background feeds (optional)
     |
 Output adapters
     |
   Wazuh / logs / files
```

Design choices:

* Deterministic time, not wall-clock time
* One event bus, many producers
* Scenarios do not know about feeds
* Feeds do not know about scenarios

It is more complex than it looks. That is the point.

## License

This project is released under [CC0 / public domain equivalent](https://creativecommons.org/publicdomain/zero/1.0/legalcode.en).

Meaning: Do what you want. Just do it well. 
