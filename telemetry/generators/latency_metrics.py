"""
Latency metrics telemetry generator.

This module emits simulated latency and jitter measurements for
router-to-router or router-to-peer paths. The metrics are intended
to complement BGP updates and syslog messages for detection and
analysis scenarios.
"""

from typing import Optional, Dict

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class LatencyMetricsGenerator:
    """
    Generator for latency-style telemetry events.

    Each emitted event is a simple dictionary compatible with the
    event bus. Values are deliberately approximate and sufficient
    for detection exercises.
    """

    def __init__(
        self,
        clock: SimulationClock,
        event_bus: EventBus,
        feed: str = "latency-metrics",
        observer: str = "simulator",
        scenario_name: Optional[str] = None,
    ) -> None:
        self.clock = clock
        self.event_bus = event_bus
        self.feed = feed
        self.observer = observer
        self.scenario_name = scenario_name

    def emit(
        self,
        source_router: str,
        target_router: str,
        latency_ms: float,
        jitter_ms: Optional[float] = None,
        packet_loss_pct: Optional[float] = None,
        attack_step: Optional[str] = None,
    ) -> None:
        """
        Emit a latency metric event.

        :param source_router: Originating router name
        :param target_router: Destination router name
        :param latency_ms: Measured latency in milliseconds
        :param jitter_ms: Optional jitter in milliseconds
        :param packet_loss_pct: Optional packet loss percentage
        :param attack_step: Optional scenario step for metadata
        """
        attributes: Dict[str, object] = {
            "source_router": source_router,
            "target_router": target_router,
            "latency_ms": latency_ms,
        }

        if jitter_ms is not None:
            attributes["jitter_ms"] = jitter_ms
        if packet_loss_pct is not None:
            attributes["packet_loss_pct"] = packet_loss_pct

        event: Dict[str, object] = {
            "event_type": "network.latency",
            "timestamp": self.clock.now(),
            "source": {"feed": self.feed, "observer": self.observer},
            "attributes": attributes,
        }

        if self.scenario_name or attack_step:
            event["scenario"] = {"name": self.scenario_name, "attack_step": attack_step}

        self.event_bus.publish(event)
