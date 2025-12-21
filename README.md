# Red Lantern simulator

Red Lantern Simulator is a deterministic attack-telemetry generator for network and routing security scenarios.

It simulates [BGP- and control-plane–related attacks](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/) and 
emits structured JSON events designed to be ingested by Wazuh for [detection engineering, rule testing, and analyst 
training](https://blue.tymyrddin.dev/docs/shadows/red-lantern/).

This project intends to produce realistic, time-ordered telemetry that *looks like* what real infrastructure 
would emit during routing incidents and attacks.

## What this repository is for

* Practising detection engineering for BGP and routing incidents
* Testing Wazuh decoders and rules against realistic attack timelines
* Teaching analysts what routing attacks look like *in logs*
* Generating repeatable datasets for workshops, labs, and exercises

## What this repository is not

* A live BGP monitoring system
* A packet-level network simulator
* A replacement for real feeds like RIS, RouteViews, or RPKI validators
* A Wazuh plugin

If you are expecting magic, you are in the wrong forest.

## Development and quality

### Linting & formatting

The project is configured with `ruff` (for linting and formatting) and `mypy` (for static type checking).

| Command                      | Purpose                                  | Configuration file |
|------------------------------|------------------------------------------|--------------------|
| `ruff check .`               | Check code for linting errors            | `pyproject.toml`   |
| `ruff check --fix .`         | Automatically fix fixable linting errors | `pyproject.toml`   |
| `ruff format .`              | Format all code according to style rules | `pyproject.toml`   |
| `mypy simulator/ telemetry/` | Run static type checking                 | `pyproject.toml`   |

*Note*: The project uses `ruff` as a unified tool that replaces both `flake8` and `isort`. All configuration is in `pyproject.toml`.

### Testing

Tests are organized in a [tests/](tests) directory with `pytest`.

| Command                                  | Purpose                           |
|------------------------------------------|-----------------------------------|
| `pytest tests/ -v`                       | Run all tests with verbose output |
| `pytest tests/unit/ -v`                  | Run only unit tests               |
| `pytest tests/integration/ -v`           | Run only integration tests        |
| `pytest --cov=simulator --cov=telemetry` | Run tests with coverage report    |

### Dependencies

- Install main dependencies: `pip install -r requirements.txt`
- Install development tools: `pip install pytest ruff mypy`

## Architecture overview

```
Scenario YAML
     │
     ▼
Scenario Runner
     │
     ▼
SimulationClock ──── schedules time
     │
     ▼
Telemetry Generators
     │
     ▼
EventBus
     │
     ▼
Structured JSON events
```

Those JSON events are the only output.

## Scenarios

Scenarios live under [simulator/scenarios/](simulator/scenarios).

Each scenario consists of:

* `scenario.yaml` – the attack timeline
* `telemetry.py` – how telemetry is emitted for that timeline
* `README.md` – what the scenario represents and what it exercises

Current scenarios include:

* Fat-finger hijack – accidental exact-prefix misorigin
* Subprefix interception – deliberate more-specific hijack with forwarding
* ROA poisoning – control-plane manipulation via RPKI and policy abuse

## Telemetry output

The simulator emits JSON objects, one per event, for example:

```json
{
  "event_type": "bgp.update",
  "timestamp": 60,
  "source": {
    "feed": "mock",
    "observer": "simulator"
  },
  "attributes": {
    "prefix": "203.0.113.128/25",
    "as_path": [65002, 65003],
    "origin_as": 65003,
    "next_hop": "198.51.100.1"
  },
  "scenario": {
    "name": "subprefix-intercept",
    "attack_step": "subprefix_announce",
    "incident_id": "subprefix-intercept-203.0.113.128/25"
  }
}
```

All emitted events are:

* Structured (no free-text-only logs)
* Timestamped
* Scenario-tagged
* Designed to be decoder-friendly

## Using this with Wazuh

1. Run the simulator
2. Capture or forward the JSON output
3. Ingest it into Wazuh
4. Apply custom decoders and rules
5. Observe alerts and correlations

## Minimal Wazuh integration approach

[Install Wazuh](https://documentation.wazuh.com/current/installation-guide/index.html). For a minimal Wazuh on a 
localhost, follow the [official quickstart](https://documentation.wazuh.com/current/quickstart.html) for a single-node 
deployment:

* Wazuh Manager
* Filebeat
* OpenSearch

No customisation needed at this stage.

If you want Wazuh on the same machine where you want to run the simulator, you do not need an agent. 
Alternatively, you install the agent and simulator on another machine.

### All-in-one deployment

The manager can monitor local files directly.

1. Create the log directory:

```bash
sudo mkdir -p /var/log/red-lantern
sudo chmod 755 /var/log/red-lantern
```

2. Configure the Wazuh Manager to monitor the file

Edit the manager's `ossec.conf`:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this inside the `<ossec_config>` section:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/red-lantern/bgp.log</location>
</localfile>
```

3. Restart the Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

Run the simulator, for example:

```bash
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml > /var/log/red-lantern/bgp.log
```

5. Verify ingestion:

Check that events are being processed:

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

### Alternative: Use a separate machine for the agent

If you want to practice the full agent-manager architecture:

1. Keep the manager on your current machine (localhost)
2. Install the agent on a different machine (VM, container, or another physical machine)
3. Point the agent to your manager's IP address (not 127.0.0.1, but your actual network IP)

To find your machine's IP:

```bash
ip addr show | grep "inet "
```

### Ingest simulator output

There are three common approaches:

#### Option 1: Pipe simulator output to a file

```bash
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml \
  > /var/log/red-lantern/bgp.log
```

Configure the Wazuh agent to monitor that file as JSON.

#### Option 2: Forward via syslog

Wrap simulator output in syslog framing and send to the Wazuh agent or manager.

#### Option 3: Inject via Filebeat

Use Filebeat JSON input pointing at the simulator output.

### Wazuh decoders

Custom decoders live under [wazuh/decoders/](wazuh/decoders).

Example:

* `bgp_decoders.xml`

These decoders:

* Match on `event_type`
* Extract fields under `attributes.*`
* Normalise fields for rule matching

They assume structured JSON, not regex soup.

### Wazuh rules (signals)

Rules live under [wazuh/rules/](wazuh/rules).

Example signals:

* Route misorigin detection
* More-specific prefix hijacks
* RPKI state changes
* Route flapping and noise masking
* Blackhole community abuse

These rules correlate multiple events over time, not single log lines.

### Alerts and analysis

Once ingested:

* Alerts appear in Wazuh dashboards
* Timelines show escalation and cleanup phases
* Analysts can replay the same scenario repeatedly

This is the point.

## Feeds

The simulator includes a [feeds directory](simulator/feeds) to model external context, such as:

* BGP collectors (RIS, RouteViews)
* Change management databases
* Future RPKI or policy feeds

These feeds:

* Do not emit telemetry directly
* Provide enrichment or alternative perspectives
* Can be swapped for real data later

They exist to keep the simulator architecture-realistic, not to fake the internet.

## Why this simulator exists

This simulator creates boring, realistic logs so defenders can practise noticing when boring suddenly is not.

## Summary

* This project simulates attacks
* It emits structured JSON telemetry
* Wazuh does the detection and alerting
* Nothing here runs in production
* Everything here is reproducible

If you can break the detections with this simulator, the internet will do worse.
