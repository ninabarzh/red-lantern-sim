# Using this with Wazuh

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

Wrap simulator output in syslog framing and send to the Wazuh agent or manager. You need to code, but only a bit.

#### Option 3: Inject via Filebeat

Use Filebeat JSON input pointing at the simulator output. You need to code, but only a bit.
