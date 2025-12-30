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
        scenario_name="Playbook 1 - BMP Route Monitoring Demo",
        clock=clock,
        bus=event_bus  # optional, EventBus will receive the generated events
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        """
        Map scenario timeline events to BMP telemetry.
        Only consume timeline entries and add structured scenario metadata.
        """
        entry = event.get("entry")
        if not entry:
            return

        # Unique incident ID for correlation
        incident_id = f"{scenario_name}-{entry.get('prefix', 'unknown')}-{entry.get('correlation_id', '0')}"

        scenario_meta = {
            "scenario_id": scenario_name,
            "scenario_name": "Playbook 1 - BMP Route Monitoring Demo",
            "incident_id": incident_id,
            "attack_type": entry.get("attack_type", "legitimate"),
            "is_malicious": entry.get("is_malicious", False),
            "attack_phase": entry.get("attack_phase", "baseline")
        }

        bmp_event_input = {
            "prefix": entry.get("prefix"),
            "as_path": entry.get("as_path", []),
            "origin_as": entry.get("origin_as"),
            "next_hop": entry.get("next_hop"),
            "peer_ip": entry.get("peer_ip"),
            "peer_as": entry.get("peer_as"),
            "peer_bgp_id": entry.get("peer_bgp_id"),
            "is_withdraw": entry.get("action") == "withdraw",
            "scenario_metadata": scenario_meta
        }

        # Emit the BMP telemetry
        for _ in bmp_gen.generate(bmp_event_input):
            pass  # EventBus already publishes inside generate()

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
