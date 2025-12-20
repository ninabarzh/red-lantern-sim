# telemetry/generators/latency_metrics.py
"""
Latency metrics generator for Red Lantern simulator.

Generates synthetic latency/jitter/packet loss events between routers.
Supports optional structured scenario metadata for correlation.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class LatencyMetricsGenerator:
    def __init__(self, clock: SimulationClock, event_bus: EventBus, scenario_name: str):
        """
        Initialize the generator.

        Args:
            clock: Shared simulation clock.
            event_bus: Shared event bus.
            scenario_name: Scenario name for correlation.
        """
        self.clock = clock
        self.event_bus = event_bus
        self.scenario_name = scenario_name

    def emit(
        self,
        source_router: str,
        target_router: str,
        latency_ms: float,
        jitter_ms: float,
        packet_loss_pct: float,
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit a synthetic latency metrics event.

        Args:
            source_router: Name of source router.
            target_router: Name of target router.
            latency_ms: Observed latency in milliseconds.
            jitter_ms: Observed jitter in milliseconds.
            packet_loss_pct: Observed packet loss percentage.
            scenario: Optional structured scenario metadata.
        """
        event = {
            "event_type": "latency.metrics",
            "timestamp": self.clock.now(),
            "source": {"feed": "mock", "observer": "simulator"},
            "attributes": {
                "source_router": source_router,
                "target_router": target_router,
                "latency_ms": latency_ms,
                "jitter_ms": jitter_ms,
                "packet_loss_pct": packet_loss_pct,
            },
            "scenario": scenario
            or {"name": self.scenario_name, "attack_step": None, "incident_id": None},
        }
        self.event_bus.publish(event)
