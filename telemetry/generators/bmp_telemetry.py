# telemetry/generators/bmp_telemetry.py
"""
BMP telemetry generator for red-lantern-sim.
Generates bmp_route_monitoring events for the BMP adapter.
"""

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BMPTelemetryGenerator:
    """Generates BMP monitoring events."""

    def __init__(
        self,
        scenario_id: str,
        scenario_name: str,
        clock: SimulationClock,
        event_bus: EventBus,
        collector_id: str = "collector-01",
    ):
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.clock = clock
        self.event_bus = event_bus
        self.collector_id = collector_id
        self.event_sequence = 0

    def generate(self, event: dict) -> None:
        """Generate a bmp_route_monitoring event.

        Args:
            event: BGP data with keys:
                - prefix: str
                - as_path: list[int]
                - origin_as: int
                - next_hop: str
                - peer_ip: str
                - peer_as: int
                - is_withdraw: bool (optional)
                - rpki_state: str (optional)
                - scenario: dict (optional)
        """
        self.event_sequence += 1

        # Emit event in format the BMP adapter expects
        bmp_event = {
            "event_type": "bmp_route_monitoring",  # What adapter expects
            "timestamp": self.clock.now(),
            "source": {"feed": "bmp-collector", "observer": self.collector_id},
            "peer_header": {
                "peer_address": event.get("peer_ip", "192.0.2.1"),
                "peer_as": event.get("peer_as", 65001),
            },
            "bgp_update": {
                "prefix": event.get("prefix"),
                "as_path": event.get("as_path", []),
                "origin_as": event.get("origin_as", 0),
                "next_hop": event.get("next_hop", "192.0.2.254"),
                "is_withdraw": event.get("is_withdraw", False),
                "peer_ip": event.get("peer_ip", "192.0.2.1"),  # For adapter
                "peer_as": event.get("peer_as", 65001),  # For adapter
            },
            "scenario": event.get("scenario")
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }

        # Add RPKI state if present
        if "rpki_state" in event:
            bmp_event["rpki_validation"] = {
                "state": event["rpki_state"],
                "validation_timestamp": self.clock.now(),
            }

        self.event_bus.publish(bmp_event)

    def reset(self):
        """Reset the generator state."""
        self.event_sequence = 0
