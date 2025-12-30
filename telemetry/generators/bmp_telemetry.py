# telemetry/generators/bmp_telemetry.py

"""
Generates BMP (BGP Monitoring Protocol) RouteMonitoring messages
from scenario events, following the red-lantern-sim telemetry pattern.
Uses the simulator clock and publishes directly to EventBus if provided.
"""

from typing import Any, Iterable

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BMPTelemetryGenerator:


    def __init__(
        self,
        scenario_id: str,
        scenario_name: str,
        clock: SimulationClock,
        bus: EventBus | None = None,
        collector_id: str = "collector-01",
        router_name: str = "edge-router-01"
    ) -> None:
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.clock = clock
        self.bus = bus
        self.collector_id = collector_id
        self.router_name = router_name
        self.event_sequence = 0

    def generate(self, event: dict[str, Any]) -> Iterable[dict[str, Any]]:
        self.event_sequence += 1
        ts_seconds = self.clock.now()
        ts_microseconds = 0  # no subsecond precision

        prefix = event["prefix"]
        prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 24
        afi = 2 if ":" in prefix else 1

        bmp_event: dict[str, Any] = {
            "event_type": "bmp_route_monitoring",
            "timestamp": str(ts_seconds),
            "bmp_version": 3,
            "message_type": "route_monitoring",
            "peer_header": {
                "peer_type": 0,
                "peer_address": event.get("peer_ip", "192.0.2.1"),
                "peer_as": event.get("peer_as", 65001),
                "peer_bgp_id": event.get("peer_bgp_id", "192.0.2.1"),
                "timestamp_seconds": ts_seconds,
                "timestamp_microseconds": ts_microseconds
            },
            "bgp_update": {
                "prefix": prefix,
                "prefix_length": prefix_len,
                "afi": afi,
                "safi": 1,
                "is_withdraw": event.get("is_withdraw", False),
                "as_path": event.get("as_path", []),
                "origin_as": event.get("origin_as", event["as_path"][-1] if event.get("as_path") else 0),
                "next_hop": event.get("next_hop", "192.0.2.254"),
                "origin": event.get("origin", "IGP")
            },
            "scenario_metadata": {
                "scenario_id": self.scenario_id,
                "scenario_name": self.scenario_name,
                "attack_phase": event.get("attack_phase", "baseline"),
                "is_malicious": event.get("is_malicious", False),
                "attack_type": event.get("attack_type", "legitimate"),
                "event_sequence_id": self.event_sequence,
                "correlation_id": event.get("correlation_id", f"{self.scenario_id}_{self.event_sequence}")
            }
        }

        for attr in ["local_pref", "med", "communities"]:
            if attr in event:
                bmp_event["bgp_update"][attr] = event[attr]

        if "rpki_state" in event:
            bmp_event["rpki_validation"] = {
                "state": event["rpki_state"],
                "validation_timestamp": str(ts_seconds)
            }

        # Correct EventBus usage
        if self.bus is not None:
            self.bus.publish(bmp_event)

        yield bmp_event

    def reset(self) -> None:
        self.event_sequence = 0
