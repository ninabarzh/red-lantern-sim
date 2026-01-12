# telemetry/generators/bgp_updates.py
"""
BGP update generator for realistic control-plane simulation.
Generates events that routers process internally.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BGPUpdateGenerator:
    def __init__(self, clock: SimulationClock, event_bus: EventBus, scenario_name: str):
        """
        Initialize the generator.

        Args:
            clock: Shared simulation clock.
            event_bus: Shared event bus.
            scenario_name: Name of the scenario for correlation.
        """
        self.clock = clock
        self.event_bus = event_bus
        self.scenario_name = scenario_name

    def emit_update(
        self,
        prefix: str,
        as_path: list[int],
        origin_as: int,
        next_hop: str,
        communities: list[str] | None = None,
        local_pref: int = 100,
        med: int = 0,
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit a realistic BGP UPDATE event.
        This represents what a router processes internally.

        Args:
            prefix: IP prefix being announced.
            as_path: List of AS numbers in the path.
            origin_as: Originating AS.
            next_hop: Next hop IP.
            communities: BGP communities.
            local_pref: Local preference value.
            med: MED value.
            scenario: Optional structured metadata.
        """
        event = {
            "event_type": "bgp.rib_update",  # Changed to more accurate name
            "timestamp": self.clock.now(),
            "source": {
                "router": "edge-router-01",
                "peer_ip": "10.0.0.2",
                "peer_as": as_path[0] if as_path else 0,
            },
            "bgp_data": {  # Realistic BGP data structure
                "type": "UPDATE",
                "prefix": prefix,
                "as_path": as_path,
                "origin_as": origin_as,
                "next_hop": next_hop,
                "communities": communities or [],
                "local_pref": local_pref,
                "med": med,
                "timestamp": self.clock.now(),
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)

    def emit_withdraw(
        self,
        prefix: str,
        origin_as: int,
        peer_ip: str = "10.0.0.2",
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit a realistic BGP WITHDRAW event.

        Args:
            prefix: IP prefix being withdrawn.
            origin_as: AS that originally announced the prefix.
            peer_ip: IP of the peer sending the withdraw.
            scenario: Optional structured metadata.
        """
        event = {
            "event_type": "bgp.rib_withdraw",  # Changed to more accurate name
            "timestamp": self.clock.now(),
            "source": {
                "router": "edge-router-01",
                "peer_ip": peer_ip,
                "peer_as": origin_as,
            },
            "bgp_data": {
                "type": "WITHDRAW",
                "prefix": prefix,
                "origin_as": origin_as,
                "timestamp": self.clock.now(),
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)
