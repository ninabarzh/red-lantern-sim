# simulator/output/adapter.py
from typing import Iterable
from .tacacs_adapter import TACACSAdapter
from .router_adapter import RouterAdapter
from .rpki_adapter import RPKIAdapter
from .cmdb_adapter import CMDBAdapter

class ScenarioAdapter:
    """Dispatch events to the proper feed adapter."""

    def __init__(self):
        self.adapters = {
            "access.login": TACACSAdapter(),
            "access.logout": TACACSAdapter(),
            "router.syslog": RouterAdapter(),
            "bgp.update": RouterAdapter(),
            "rpki.validation": RPKIAdapter(),
            "cmdb.change": CMDBAdapter(),
        }

    def transform(self, event: dict) -> list[str]:
        adapter = self.adapters.get(event.get("event_type"))
        if adapter:
            return list(adapter.transform(event))
        return []

def write_scenario_logs(events: Iterable[dict], output_file_path: str) -> None:
    from pathlib import Path
    import sys
    adapter = ScenarioAdapter()
    output_file = Path(output_file_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for event in events:
            try:
                for line in adapter.transform(event):
                    if line:
                        f.write(line + "\n")
            except Exception as e:
                print(f"Warning: failed to transform event {event}: {e}", file=sys.stderr)
