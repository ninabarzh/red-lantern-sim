"""
BGP UPDATE and WITHDRAW telemetry generator.

This module produces schema-compliant BGP events for use by the simulator.
It does not attempt to model the full BGP state machine. That way lies
madness and vendor documentation.

Instead, it emits just enough structure to support realistic detection
signals and chained attack scenarios.
"""

from typing import Optional, List, Dict

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BGPUpdateGenerator:
    """
    Generator for BGP UPDATE and WITHDRAW events.

    Each emitted event conforms to telemetry/schemas/bgp_event.json.
    The generator is intentionally opinionated about what fields matter
    for detection and correlation.
    """

    def __init__(
        self,
        clock: SimulationClock,
        event_bus: EventBus,
        feed: str = "mock",
        observer: str = "simulator",
        scenario_name: Optional[str] = None,
    ) -> None:
        self.clock = clock
        self.event_bus = event_bus
        self.feed = feed
        self.observer = observer
        self.scenario_name = scenario_name

    def emit_update(
        self,
        prefix: str,
        as_path: List[int],
        origin_as: int,
        next_hop: str,
        local_pref: Optional[int] = None,
        med: Optional[int] = None,
        attack_step: Optional[str] = None,
    ) -> None:
        """
        Emit a BGP UPDATE event.

        :param prefix: The announced IP prefix (e.g., '203.0.113.0/24')
        :param as_path: List of AS numbers forming the AS_PATH
        :param origin_as: Originating AS number
        :param next_hop: Next hop IP address
        :param local_pref: Optional local preference
        :param med: Optional MED attribute
        :param attack_step: Optional step name for scenario tracking
        """
        attributes: Dict[str, object] = {
            "prefix": prefix,
            "as_path": as_path,
            "origin_as": origin_as,
            "next_hop": next_hop,
        }

        if local_pref is not None:
            attributes["local_pref"] = local_pref
        if med is not None:
            attributes["med"] = med

        event: Dict[str, object] = {
            "event_type": "bgp.update",
            "timestamp": self.clock.now(),
            "source": {"feed": self.feed, "observer": self.observer},
            "attributes": attributes,
        }

        if self.scenario_name or attack_step:
            event["scenario"] = {"name": self.scenario_name, "attack_step": attack_step}

        self.event_bus.publish(event)

    def emit_withdraw(
        self,
        prefix: str,
        withdrawn_by_as: int,
        attack_step: Optional[str] = None,
    ) -> None:
        """
        Emit a BGP WITHDRAW event.

        :param prefix: The withdrawn IP prefix
        :param withdrawn_by_as: AS number withdrawing the route
        :param attack_step: Optional step name for scenario tracking
        """
        attributes: Dict[str, object] = {
            "prefix": prefix,
            "withdrawn_by_as": withdrawn_by_as,
        }

        event: Dict[str, object] = {
            "event_type": "bgp.withdraw",
            "timestamp": self.clock.now(),
            "source": {"feed": self.feed, "observer": self.observer},
            "attributes": attributes,
        }

        if self.scenario_name or attack_step:
            event["scenario"] = {"name": self.scenario_name, "attack_step": attack_step}

        self.event_bus.publish(event)
