# README

Modular log adapter system for Red Lantern simulator events.

## Structure

- **base.py**: Base Adapter class.
- **tacacs_adapter.py**: TACACS syslog lines for access.login/logout.
- **router_adapter.py**: Router syslog and BGP update lines.
- **rpki_adapter.py**: RPKI validation events.
- **cmdb_adapter.py**: CMDB/change management events.
- **adapter.py**: ScenarioAdapter dispatching to proper feed adapter.
- **test_adapter.py**: Simple CLI test harness.
- **__init__.py**: Exports all classes and helpers.

## Usage

### Transform scenario events into logs:

```python
from simulator.output.adapter import write_scenario_logs

events = [...]  # list of simulator scenario events
write_scenario_logs(events, "output/logs/merged.log")
````

### Test from CLI:

In root project:

```bash
python -m simulator.cli simulator/scenarios/[...] | python -m simulator.output.test_adapter
```

* Produces log lines for multiple event types.
* Modular design allows adding new adapters easily.
