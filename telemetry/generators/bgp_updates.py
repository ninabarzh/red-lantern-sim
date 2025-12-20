# telemetry/generators/bgp_updates.py
"""
BGP update generator for Red Lantern simulator.

This generator emits BGP UPDATE and WITHDRAW events to the EventBus.
Future-proofed to allow optional structured scenario metadata.
"""

from typing import Any, Dict
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
        scenario: Dict[str, Any] | None = None,
    ):
        """
        Emit a BGP UPDATE event.

        Args:
            prefix: IP prefix being announced.
            as_path: List of AS numbers in the path.
            origin_as: Originating AS.
            next_hop: Next hop IP.
            scenario: Optional structured metadata (attack_step, incident_id, etc.)
        """
        event = {
            "event_type": "bgp.update",
            "timestamp": self.clock.now(),
            "source": {"feed": "mock", "observer": "simulator"},
            "attributes": {
                "prefix": prefix,
                "as_path": as_path,
                "origin_as": origin_as,
                "next_hop": next_hop,
            },
            "scenario": scenario
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }
        self.event_bus.publish(event)

    def emit_withdraw(
        self, prefix: str, withdrawn_by_as: int, scenario: Dict[str, Any] | None = None
    ):
        """
        Emit a BGP WITHDRAW event.

        Args:
            prefix: IP prefix being withdrawn.
            withdrawn_by_as: AS withdrawing the prefix.
            scenario: Optional structured metadata.
        """
        event = {
            "event_type": "bgp.withdraw",
            "timestamp": self.clock.now(),
            "source": {"feed": "mock", "observer": "simulator"},
            "attributes": {
                "prefix": prefix,
                "withdrawn_by_as": withdrawn_by_as,
            },
            "scenario": scenario
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }
        self.event_bus.publish(event)
