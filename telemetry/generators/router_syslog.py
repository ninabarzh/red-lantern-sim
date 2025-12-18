"""
Router syslog telemetry generator.

This module emits intentionally messy, human-shaped syslog messages that
approximate what real routers tend to produce during routing incidents.
These events complement structured BGP updates and exist primarily to
exercise log-based detection and correlation rules in Wazuh.

Accuracy is sacrificed in favour of realism. If it looks plausible to an
on-call engineer at 03:00, it is good enough.
"""

from typing import Optional, Dict

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class RouterSyslogGenerator:
    """
    Generator for router-style syslog messages.

    Messages are emitted as generic telemetry events with free-form
    attributes. Downstream tooling is expected to parse, normalise, and
    occasionally misinterpret them.
    """

    def __init__(
        self,
        clock: SimulationClock,
        event_bus: EventBus,
        router_name: str,
        feed: str = "router-syslog",
        observer: str = "router",
        scenario_name: Optional[str] = None,
    ) -> None:
        self.clock = clock
        self.event_bus = event_bus
        self.router_name = router_name
        self.feed = feed
        self.observer = observer
        self.scenario_name = scenario_name

    def emit(
        self,
        severity: str,
        message: str,
        subsystem: Optional[str] = None,
        peer_ip: Optional[str] = None,
        attack_step: Optional[str] = None,
    ) -> None:
        """
        Emit a raw syslog-style message.
        """
        attributes: Dict[str, object] = {
            "router": self.router_name,
            "severity": severity,
            "message": message,
        }
        if subsystem:
            attributes["subsystem"] = subsystem
        if peer_ip:
            attributes["peer_ip"] = peer_ip

        event: Dict[str, object] = {
            "event_type": "router.syslog",
            "timestamp": self.clock.now(),
            "source": {"feed": self.feed, "observer": self.observer},
            "attributes": attributes,
        }

        if self.scenario_name or attack_step:
            event["scenario"] = {"name": self.scenario_name, "attack_step": attack_step}

        self.event_bus.publish(event)

    # Convenience helpers

    def bgp_session_reset(self, peer_ip: str, reason: str, attack_step: Optional[str] = None) -> None:
        """
        Emit a warning that a BGP session has been reset.
        """
        self.emit(
            severity="warning",
            message=f"BGP session to {peer_ip} reset: {reason}",
            subsystem="bgp",
            peer_ip=peer_ip,
            attack_step=attack_step,
        )

    def prefix_limit_exceeded(self, peer_ip: str, limit: int, attack_step: Optional[str] = None) -> None:
        """
        Emit an error indicating a prefix limit exceeded condition.
        """
        self.emit(
            severity="error",
            message=f"Prefix limit {limit} exceeded from neighbour {peer_ip}",
            subsystem="bgp",
            peer_ip=peer_ip,
            attack_step=attack_step,
        )

    def configuration_change(self, user: str, change_summary: str, attack_step: Optional[str] = None) -> None:
        """
        Emit an informational event describing a configuration change.
        """
        self.emit(
            severity="info",
            message=f"Configuration change by {user}: {change_summary}",
            subsystem="config",
            attack_step=attack_step,
        )
