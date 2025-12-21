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

If you want Wazuh on the same machine where you want to run the simulator, you do not need an agent. The manager can 
monitor local files directly. Alternatively, you install the agent and simulator on another machine.

### All-in-one deployment

It is simpler and accomplishes exactly what you want: getting your simulator's JSON events into Wazuh for decoder/rule 
testing. 

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

Add this inside the `<ossec_config>` section (localfiles are at the bottom):

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
sudo chown -R $USER:$USER /var/log/red-lantern
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml > /var/log/red-lantern/bgp.log
```

5. Verify ingestion:

Check that events are being processed:

```bash
sudo tail -f /var/ossec/logs/ossec.log
...[snip]
2025/12/21 12:18:33 wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/red-lantern/bgp.log'.
...[snip]
2025/12/21 12:18:39 wazuh-syscheckd: INFO: (6009): File integrity monitoring scan ended.
2025/12/21 12:18:39 wazuh-syscheckd: INFO: FIM sync module started.
2025/12/21 12:18:41 sca: INFO: Evaluation finished for policy '/var/ossec/ruleset/sca/cis_ubuntu24-04.yml'
2025/12/21 12:18:41 sca: INFO: Security Configuration Assessment scan finished. Duration: 6 seconds.
2025/12/21 12:20:30 rootcheck: INFO: Ending rootcheck scan.
```

You won't see the events in `ossec.log` - that only shows service startup/shutdown messages. To see your actual BGP 
events being processed, check the archives or manually check logs:

```bash
$ head -3 /var/log/red-lantern/bgp.log | sudo /var/ossec/bin/wazuh-logtest
Starting wazuh-logtest v4.14.1
Type one log per line


**Phase 1: Completed pre-decoding.
        full event: '{"timestamp": 0, "scenario_id": "fat-finger-hijack", "entry": {"t": 0, "action": "start"}}'

**Phase 2: Completed decoding.
        name: 'json'
        entry.action: 'start'
        entry.t: '0'
        scenario_id: 'fat-finger-hijack'
        timestamp: '0'


**Phase 1: Completed pre-decoding.
        full event: '{"timestamp": 10, "scenario_id": "fat-finger-hijack", "entry": {"t": 10, "action": "announce", "prefix": "203.0.113.0/24", "attacker_as": 65002, "victim_as": 65001, "note": "Exact-prefix announcement, looks like operator error"}}'

**Phase 2: Completed decoding.
        name: 'json'
        entry.action: 'announce'
        entry.attacker_as: '65002'
        entry.note: 'Exact-prefix announcement, looks like operator error'
        entry.prefix: '203.0.113.0/24'
        entry.t: '10'
        entry.victim_as: '65001'
        scenario_id: 'fat-finger-hijack'
        timestamp: '10'

**Phase 3: Completed filtering (rules).
        id: '1002'
        level: '2'
        description: 'Unknown problem somewhere in the system.'
        groups: '['syslog', 'errors']'
        firedtimes: '1'
        gpg13: '['4.3']'
        mail: 'False'


**Phase 1: Completed pre-decoding.

**Phase 2: Completed decoding.
        name: 'json'
        attributes.as_path: '[65002]'
        attributes.next_hop: '192.0.2.1'
        attributes.origin_as: '65002'
        attributes.prefix: '203.0.113.0/24'
        event_type: 'bgp.update'
        scenario.attack_step: 'misorigin'
        scenario.incident_id: 'fat-finger-hijack-203.0.113.0/24'
        scenario.name: 'fat-finger-hijack'
        source.feed: 'mock'
        source.observer: 'simulator'
        timestamp: '10'

**Phase 3: Completed filtering (rules).
        id: '86600'
        level: '0'
        description: 'Suricata messages.'
        groups: '['ids', 'suricata']'
        firedtimes: '1'
        mail: 'False'
```

The BGP events are matching generic/irrelevant rules:

- Rule 1002: "Unknown problem somewhere in the system" (generic error rule)
- Rule 86600: "Suricata messages" (IDS rule - wrong category!)

That is correct. Custom Decoders & Rules have not been installed yet. See below.

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

## Installing the custom decoders & rules

### Install the BGP Decoders

Custom decoders live under [wazuh/decoders/](wazuh/decoders) in the repo. These decoders assume structured JSON, 
not regex soup. They:

* Match on `event_type`
* Extract fields under `attributes.*`
* Normalise fields for rule matching

```bash
sudo wget https://raw.githubusercontent.com/ninabarzh/red-lantern-sim/refs/heads/main/wazuh/decoders/bgp_decoders.xml -O /var/ossec/etc/decoders/local_decoder.xml
```

### Install the three signal rule files

Some predefined rules for the initial three scenarios live under [wazuh/rules/](wazuh/rules) in the repo. These rules 
correlate multiple events over time, not single log lines. Example signals:

* Route misorigin detection
* More-specific prefix hijacks
* RPKI state changes
* Route flapping and noise masking
* Blackhole community abuse

For Signal One (Fat-Finger Hijacks):

```bash
sudo wget https://raw.githubusercontent.com/ninabarzh/red-lantern-sim/refs/heads/main/wazuh/rules/signal_one.xml -O /var/ossec/etc/rules/bgp_signal_one.xml
```

For Signal Two (Subprefix Interception):

```bash
sudo wget https://raw.githubusercontent.com/ninabarzh/red-lantern-sim/refs/heads/main/wazuh/rules/signal_two.xml -O /var/ossec/etc/rules/bgp_signal_two.xml
```

For Signal Three (Control-Plane Poisoning):

```bash
sudo wget https://raw.githubusercontent.com/ninabarzh/red-lantern-sim/refs/heads/main/wazuh/rules/signal_three.xml -O /var/ossec/etc/rules/bgp_signal_three.xml
```

### Checks

Verify the files:

```bash
sudo ls -lh /var/ossec/etc/decoders/local_decoder.xml
sudo ls -lh /var/ossec/etc/rules/bgp_signal_one.xml
sudo ls -lh /var/ossec/etc/rules/bgp_signal_two.xml
sudo ls -lh /var/ossec/etc/rules/bgp_signal_three.xml
```

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

Check status:

```bash
sudo systemctl status wazuh-manager
```

Test with events:

```bash
head -5 /var/log/red-lantern/bgp.log | sudo /var/ossec/bin/wazuh-logtest
```

Now you should see your custom rules like:

- **Rule 100001**: BGP UPDATE detected
- **Rule 100002**: BGP WITHDRAW detected  
- **Rule 100008**: Prefix limit exceeded (from signal_one.xml)

These are the actual decoders and rules designed for the simulator! 

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
