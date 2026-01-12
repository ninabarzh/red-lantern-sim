# simulator/output/adapter.py
from collections.abc import Iterable

from .bmp_adapter import BMPAdapter
from .cmdb_adapter import CMDBAdapter
from .internal_adapter import InternalAdapter
from .monitoring_adapter import MonitoringAdapter
from .router_adapter import RouterAdapter
from .rpki_adapter import RPKIAdapter
from .tacacs_adapter import TACACSAdapter


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
            "internal.documentation": InternalAdapter(),  # Use RPKI adapter for comment-style output
            "internal.phase_complete": InternalAdapter(),
            "internal.monitoring_status": InternalAdapter(),
            "internal.phase_transition": InternalAdapter(),
            # Monitoring effects
            "monitoring.anomaly": MonitoringAdapter(),
        }

    def transform(self, event: dict) -> list[str]:
        event_type = event.get("event_type")

        # Handle training.note events - they already have formatted lines
        if event_type == "training.note":
            line = event.get("line")
            return [line] if line else []

        adapter = self.adapters.get(event_type)
        if adapter:
            return list(adapter.transform(event))
        return []


def write_scenario_logs(events: Iterable[dict], output_file_path: str) -> None:
    import sys
    from pathlib import Path

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
                print(
                    f"Warning: failed to transform event {event}: {e}", file=sys.stderr
                )
