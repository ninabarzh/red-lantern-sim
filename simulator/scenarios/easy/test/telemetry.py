"""
Telemetry mapping for Playbook 1

Maps timeline events to structured BMP RouteMonitoring messages.
"""

from typing import Any
from simulator.engine.event_bus import EventBus
from simulator.engine.clock import SimulationClock
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """
    Register BMP telemetry generator for Playbook 1 scenario.
    Maps timeline events to structured BMP RouteMonitoring messages.
    """
    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 1",
        clock=clock,
        event_bus=event_bus
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        """
        Map scenario timeline events to BMP telemetry.
        Only consume timeline entries and add structured scenario metadata.
        """
        entry = event.get("entry")
        if not entry:
            return

        prefix = entry.get("prefix")
        incident_id = f"{scenario_name}-{prefix}-{entry.get('correlation_id', '0')}"

        bmp_event_input = {
            "prefix": prefix,
            "as_path": entry.get("as_path", []),
            "origin_as": entry.get("origin_as"),
            "next_hop": entry.get("next_hop"),
            "peer_ip": entry.get("peer_ip"),
            "peer_as": entry.get("peer_as"),
            "peer_bgp_id": entry.get("peer_bgp_id"),
            "is_withdraw": entry.get("action") == "withdraw",
            "scenario": {
                "name": scenario_name,
                "attack_step": "malicious_announce" if entry.get("is_malicious") else "baseline",
                "incident_id": incident_id,
            }
        }

        # Emit the BMP telemetry
        bmp_gen.generate(bmp_event_input)

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
