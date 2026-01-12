# telemetry/generators/router_syslog.py
"""
Router syslog generator for Red Lantern simulator.
Emits STRUCTURED events for adapters to format.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class RouterSyslogGenerator:
    def __init__(
        self,
        clock: SimulationClock,
        event_bus: EventBus,
        router_name: str,
        scenario_name: str,
    ):
        """
        Initialize the generator.

        Args:
            clock: Shared simulation clock.
            event_bus: Shared event bus.
            router_name: Name of the router emitting logs.
            scenario_name: Scenario name for correlation.
        """
        self.clock = clock
        self.event_bus = event_bus
        self.router_name = router_name
        self.scenario_name = scenario_name

    def bgp_neighbor_state_change(
        self,
        peer_ip: str,
        state: str,  # "up" or "down"
        reason: str = "",
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit STRUCTURED BGP neighbor state change event.
        Adapter will format this into a log line.
        """
        event = {
            "event_type": "router.syslog",
            "timestamp": self.clock.now(),
            "source": {"feed": "router-syslog", "observer": "router"},
            "attributes": {
                "router": self.router_name,
                "severity": "warning" if state == "down" else "notice",
                "subsystem": "bgp",
                "peer_ip": peer_ip,
                "bgp_event": "neighbor_state_change",  # STRUCTURED
                "neighbor_state": state,  # STRUCTURED
                "change_reason": reason,  # STRUCTURED
            },
            "scenario": scenario
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }
        self.event_bus.publish(event)

    def configuration_change(
        self,
        user: str,
        change_type: str,  # STRUCTURED: "roa_request", "bgp_config", etc.
        target: str,  # STRUCTURED: what was changed
        attack_step: str | None = None,
    ) -> None:
        """
        Emit STRUCTURED configuration change event.
        """
        event = {
            "event_type": "router.syslog",
            "timestamp": self.clock.now(),
            "source": {"feed": "router-syslog", "observer": "router"},
            "attributes": {
                "router": self.router_name,
                "severity": "notice",
                "subsystem": "config",
                "config_event": "change",  # STRUCTURED
                "changed_by": user,  # STRUCTURED
                "change_type": change_type,  # STRUCTURED
                "change_target": target,  # STRUCTURED
            },
            "scenario": {
                "name": self.scenario_name,
                "attack_step": attack_step,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)
