# simulator/output/adapter.py
from typing import Iterable
from .tacacs_adapter import TACACSAdapter
from .router_adapter import RouterAdapter
from .rpki_adapter import RPKIAdapter
from .cmdb_adapter import CMDBAdapter
from .bmp_adapter import BMPAdapter


class ScenarioAdapter:
    """Dispatch events to the proper feed adapter."""

    def __init__(self):
        self.adapters = {
            # Access/authentication
            "access.login": TACACSAdapter(),
            "access.logout": TACACSAdapter(),

            # Router/BGP
            "router.syslog": RouterAdapter(),
            "bgp.update": RouterAdapter(),

            # RPKI events
            "rpki.validation": RPKIAdapter(),
            "rpki.query": RPKIAdapter(),
            "rpki.roa_creation": RPKIAdapter(),
            "rpki.roa_published": RPKIAdapter(),
            "rpki.validator_sync": RPKIAdapter(),

            # Registry events
            "registry.whois": RPKIAdapter(),  # WHOIS goes through RPKI adapter

            # Infrastructure
            "cmdb.change": CMDBAdapter(),

            # BMP telemetry
            "bmp_route_monitoring": BMPAdapter(),

            # Internal/documentation events
            "internal.documentation": RPKIAdapter(),  # Use RPKI adapter for comment-style output
            "internal.phase_transition": RPKIAdapter(),
            "internal.phase_complete": RPKIAdapter(),
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
