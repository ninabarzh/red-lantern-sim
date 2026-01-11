# telemetry/generators/bmp_telemetry.py
"""BMP telemetry generator for red-lantern-sim.

Generates BMP (BGP Monitoring Protocol) RouteMonitoring messages
conforming to RFC 7854 based on scenario-defined BGP events.
"""

from datetime import datetime, timezone

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BMPTelemetryGenerator:
    """Generates BMP RouteMonitoring messages from scenario events."""

    def __init__(
        self,
        scenario_id: str,
        scenario_name: str,
        clock: SimulationClock,
        event_bus: EventBus,
        collector_id: str = "collector-01",
        router_name: str = "edge-router-01",
    ):
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.clock = clock
        self.event_bus = event_bus
        self.collector_id = collector_id
        self.router_name = router_name
        self.event_sequence = 0

    def generate(self, event: dict) -> None:
        """Generate a BMP event from a scenario event definition.

        Args:
            event: Event dict from scenario telemetry.py with keys:
                - prefix: str
                - as_path: list[int]
                - origin_as: int
                - next_hop: str
                - peer_ip: str
                - peer_as: int
                - peer_bgp_id: str
                - is_withdraw: bool (optional)
                - local_pref: int (optional)
                - med: int (optional)
                - communities: list[str] (optional)
                - rpki_state: str (optional)
                - scenario: dict (optional, contains attack_step, incident_id)
        """
        self.event_sequence += 1

        ts_seconds = self.clock.now()
        ts_microseconds = 0

        # Parse prefix
        prefix = event["prefix"]
        prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 24

        # Determine AFI (IPv4=1, IPv6=2)
        afi = 2 if ":" in prefix else 1

        # Build BMP event
        bmp_event = {
            "event_type": "bmp_route_monitoring",
            "timestamp": ts_seconds,
            "source": {"feed": "bmp-collector", "observer": self.collector_id},
            "peer_header": {
                "peer_type": 0,
                "peer_address": event.get("peer_ip", "192.0.2.1"),
                "peer_as": event.get("peer_as", 65001),
                "peer_bgp_id": event.get("peer_bgp_id", "192.0.2.1"),
                "timestamp_seconds": ts_seconds,
                "timestamp_microseconds": ts_microseconds,
            },
            "bgp_update": {
                "prefix": prefix,
                "prefix_length": prefix_len,
                "afi": afi,
                "safi": 1,
                "is_withdraw": event.get("is_withdraw", False),
                "as_path": event.get("as_path", []),
                "origin_as": event.get(
                    "origin_as", event["as_path"][-1] if event.get("as_path") else 0
                ),
                "next_hop": event.get("next_hop", "192.0.2.254"),
                "origin": event.get("origin", "IGP"),
            },
            "scenario": event.get("scenario")
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }

        # Add optional BGP attributes if present
        if "local_pref" in event:
            bmp_event["bgp_update"]["local_pref"] = event["local_pref"]

        if "med" in event:
            bmp_event["bgp_update"]["med"] = event["med"]

        if "communities" in event:
            bmp_event["bgp_update"]["communities"] = event["communities"]

        # Add RPKI validation if present
        if "rpki_state" in event:
            bmp_event["rpki_validation"] = {
                "state": event["rpki_state"],
                "validation_timestamp": ts_seconds,
            }

        self.event_bus.publish(bmp_event)

    def reset(self):
        """Reset the generator state."""
        self.event_sequence = 0
