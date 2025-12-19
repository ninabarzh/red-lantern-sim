# Telemetry

This folder contains   telemetry components   for the simulator: generators and schemas. Generators produce synthetic events that simulate network, router, and operational behaviour. Schemas define the expected structure of these events to ensure consistency and facilitate ingestion (e.g., into Wazuh).

## Structure

* `generators/` – Python classes that produce events and push them to the `EventBus`.
* `schemas/` – JSON schema files defining the structure of specific events.
* `__init__.py` – package initialisation.

## Telemetry generators

Generators emit structured JSON events at scheduled simulation times using the shared `SimulationClock`.

### Existing generators

* `bgp_updates.py` – BGP UPDATE and WITHDRAW events.
* `router_syslog.py` – Router syslog messages (info, notice, warning, error, critical).
* `latency_metrics.py` – Network performance metrics (latency, jitter, packet loss).

### How a generator works

1.   Create a class   that accepts:

   * `clock`: the `SimulationClock` instance.
   * `event_bus`: the `EventBus` instance.
   * `scenario_name`: scenario context.
   * Any generator-specific parameters (e.g., `router_name` for syslog).

2.   Schedule events  :

   * Push events immediately via `self.event_bus.emit(event_dict)`
   * Or schedule future events using `self.clock.schedule(timestamp, callback,   kwargs)`.

3.   Format events   consistently for Wazuh ingestion:

   ```json
   {
       "event_type": "bgp.update",
       "timestamp": 10,
       "source": {"feed": "mock", "observer": "simulator"},
       "attributes": {"prefix": "203.0.113.0/24", "as_path": [65001], "origin_as": 65001, "next_hop": "192.0.2.1"},
       "scenario": {"name": "fat-finger-hijack", "attack_step": "misorigin", "incident_id": "fat-finger-hijack-203.0.113.0/24"}
   }
   ```

4.   Emit events   to the EventBus, which distributes them to subscribers.

### Template for a new generator

```python
from simulator.engine.event_bus import EventBus
from simulator.engine.clock import SimulationClock

class MyCustomGenerator:
    def __init__(self, clock: SimulationClock, event_bus: EventBus, scenario_name: str,   kwargs):
        self.clock = clock
        self.event_bus = event_bus
        self.scenario_name = scenario_name
        self.router_name = kwargs.get("router_name", "R1")
    
    def emit_event(self, timestamp: int,   attributes):
        event = {
            "event_type": "custom.event",
            "timestamp": timestamp,
            "source": {"feed": "custom-generator", "observer": self.router_name},
            "attributes": attributes,
            "scenario": {"name": self.scenario_name, "attack_step": "custom_step", "incident_id": "unknown"}
        }
        self.event_bus.emit(event)

    def schedule_events(self):
        self.clock.schedule(10, self.emit_event, message="first event")
        self.clock.schedule(20, self.emit_event, message="second event")
```

### Registering a generator in a scenario

```python
from simulator.engine.event_bus import EventBus
from telemetry.generators.my_custom_generator import MyCustomGenerator

def register(event_bus: EventBus, clock, scenario_name: str):
    my_gen = MyCustomGenerator(clock=clock, event_bus=event_bus, scenario_name=scenario_name)
    my_gen.schedule_events()
```

## Telemetry schemas

Schemas define the   structure and validation rules   for events. They ensure that events emitted by generators are consistent and Wazuh-ingestible.

### Existing schemas

* `bgp_event.json` – Defines the fields, types, and required attributes for BGP update/withdraw events.

### Adding a new schema

1. Create a new JSON file in `telemetry/schemas/`, e.g., `latency_event.json`.
2. Define your schema using [JSON Schema](https://json-schema.org/):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Latency Event",
  "type": "object",
  "required": ["event_type", "timestamp", "source", "attributes", "scenario"],
  "properties": {
    "event_type": {"type": "string"},
    "timestamp": {"type": "number"},
    "source": {
      "type": "object",
      "properties": {
        "feed": {"type": "string"},
        "observer": {"type": "string"}
      },
      "required": ["feed", "observer"]
    },
    "attributes": {
      "type": "object",
      "properties": {
        "source_router": {"type": "string"},
        "target_router": {"type": "string"},
        "latency_ms": {"type": "number"},
        "jitter_ms": {"type": "number"},
        "packet_loss_pct": {"type": "number"}
      },
      "required": ["source_router", "target_router", "latency_ms"]
    },
    "scenario": {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "attack_step": {"type": "string"},
        "incident_id": {"type": "string"}
      },
      "required": ["name", "attack_step"]
    }
  }
}
```

3. Reference the schema in your generators or validation code if you want automated checks before emitting events.
