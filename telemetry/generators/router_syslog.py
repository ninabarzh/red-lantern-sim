# telemetry/generators/router_syslog.py
"""
Router syslog generator for Red Lantern simulator.

Generates syslog events related to BGP, such as session resets and prefix limits.
Supports optional structured scenario metadata for future-proofing.
"""

from typing import Any, Dict
from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class RouterSyslogGenerator:
    def __init__(self, clock: SimulationClock, event_bus: EventBus, router_name: str, scenario_name: str):
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

    def emit(self, message: str, severity: str = "info", subsystem: str | None = None, peer_ip: str | None = None, scenario: Dict[str, Any] | None = None):
        """
        Emit a generic syslog event.

        Args:
            message: Log message.
            severity: syslog severity (info, notice, warning, error).
            subsystem: Optional subsystem name (e.g., bgp).
            peer_ip: Optional peer IP for BGP messages.
            scenario: Optional structured metadata (attack_step, incident_id, etc.)
        """
        event = {
            "event_type": "router.syslog",
            "timestamp": self.clock.now(),
            "source": {"feed": "router-syslog", "observer": "router"},
            "attributes": {
                "router": self.router_name,
                "severity": severity,
                "message": message,
                "subsystem": subsystem,
                "peer_ip": peer_ip,
            },
            "scenario": scenario or {"name": self.scenario_name, "attack_step": None, "incident_id": None}
        }
        self.event_bus.publish(event)

    def prefix_limit_exceeded(self, peer_ip: str, limit: int, scenario: Dict[str, Any] | None = None):
        """
        Emit an ERROR for exceeding prefix limit.

        Args:
            peer_ip: Peer that exceeded the limit.
            limit: Prefix limit configured.
            scenario: Optional structured metadata.
        """
        self.emit(
            message=f"Prefix limit {limit} exceeded from neighbour {peer_ip}",
            severity="error",
            subsystem="bgp",
            peer_ip=peer_ip,
            scenario=scenario
        )

    def bgp_session_reset(self, peer_ip: str, reason: str, scenario: Dict[str, Any] | None = None):
        """
        Emit a WARNING for BGP session reset.

        Args:
            peer_ip: Peer whose session reset.
            reason: Reason for reset.
            scenario: Optional structured metadata.
        """
        self.emit(
            message=f"BGP session to {peer_ip} reset: {reason}",
            severity="warning",
            subsystem="bgp",
            peer_ip=peer_ip,
            scenario=scenario
        )
