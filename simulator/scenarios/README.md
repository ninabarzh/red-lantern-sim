# Scenarios

Scenarios define *what happens* in the simulator.

Each scenario models a specific incident or attack pattern by describing:

- the timeline of events
- the roles involved (victim, attacker, bystanders)
- the telemetry that should be emitted as the situation unfolds

Scenarios do **not** implement simulation mechanics. They describe behaviour. The engine executes it.

## Directory structure

```
scenarios/
├── easy/
│   └── fat_finger_hijack/
│       ├── README.md
│       ├── scenario.yaml
│       └── telemetry.py
├── medium/
│   └── subprefix_intercept/
│       ├── README.md
│       ├── scenario.yaml
│       └── telemetry.py
└── advanced/
    └── roa_poisoning/
        ├── README.md
        ├── scenario.yaml
        └── telemetry.py
```

Difficulty levels are organisational only. The simulator does not treat them differently.

## Required files

### `scenario.yaml` (mandatory)

The scenario definition.

This file describes:

- scenario metadata (name, description, difficulty)
- the sequence of events
- event timing and ordering
- event payloads passed to telemetry

The engine (`scenario_runner.py`) reads this file and schedules events on the global simulation clock.

If this file is missing or malformed, nothing happens.

### `telemetry.py` (strongly recommended)

Scenario-specific telemetry logic.

This file:

- subscribes to scenario events
- translates events into realistic telemetry
- emits Wazuh-ingestible JSON via telemetry generators

Telemetry is where realism lives. A scenario without telemetry is a silent incident.

### `README.md` (recommended)

Human-readable explanation of:

- what the scenario represents
- what is being simulated
- what detections or signals it is meant to exercise

If you need to explain intent in YAML, you are already in trouble.

## Execution model

1. The simulator loads `scenario.yaml`
2. Events are scheduled on the simulation clock
3. Events are published on the event bus
4. `telemetry.py` listens for relevant events
5. Telemetry generators emit structured JSON
6. Wazuh ingests and correlates the data

Scenarios never emit telemetry directly. Telemetry never controls the clock. Everyone stays in their lane.

## What scenarios should model

Good scenarios focus on:

- attacker behaviour
- operator mistakes
- delayed or partial propagation
- ambiguity and uncertainty

Bad scenarios:

- emit “attack detected” messages
- skip intermediate steps
- rely on perfect global visibility

If it is obvious, it is unrealistic.

## Using feeds in scenarios

Scenarios may optionally use feeds to enrich telemetry.

Examples:

- expected BGP origin AS
- baseline AS paths
- configuration ownership
- collector visibility

Feeds provide context. Telemetry decides what to emit. The engine does neither.

## Adding a new scenario

1. Create a new folder under the appropriate difficulty
2. Add `scenario.yaml`
3. Add `telemetry.py`
4. Optionally add a README explaining intent
5. Run the simulator and verify output is edible by Wazuh

If your scenario cannot be detected or explained, it is not finished.

## Design principle

Scenarios exist to make detection *interesting* and help analysts and rules to distinguish:

- mistake vs attack
- noise vs signal
- coincidence vs intent

If it feels clean, it is wrong.
