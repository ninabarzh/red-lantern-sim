# simulator/scenarios/easy/fat_finger_hijack/telemetry.py
"""
Telemetry mapping for the Fat Finger Hijack scenario.

Converts scenario timeline events into structured telemetry using the
future-proof generators with structured `scenario` metadata fields.
"""

from typing import Any
from simulator.engine.event_bus import EventBus
from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


def register(event_bus: EventBus, clock, scenario_name: str):
    """
    Register the scenario telemetry with the event bus.

    Args:
        event_bus: The shared EventBus instance.
        clock: Shared simulation clock.
        scenario_name: Name of the scenario.
    """

    # Initialize generators
    bgp_gen = BGPUpdateGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )
    syslog_gen = RouterSyslogGenerator(
        clock=clock, event_bus=event_bus, router_name="R1", scenario_name=scenario_name
    )
    latency_gen = LatencyMetricsGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )

    def on_timeline_event(event: dict[str, Any]):
        """
        Map scenario timeline events to structured telemetry.
        """
        entry = event.get("entry")
        if not entry:
            return

        prefix = entry.get("prefix")
        action = entry.get("action")
        if not prefix or not action:
            return

        # Unique incident ID for correlation
        incident_id = f"{scenario_name}-{prefix}"

        if action == "announce":
            scenario_meta = {
                "name": scenario_name,
                "attack_step": "misorigin",
                "incident_id": incident_id,
            }

            # Emit BGP update
            bgp_gen.emit_update(
                prefix=prefix,
                as_path=[65002],
                origin_as=65002,
                next_hop="192.0.2.1",
                scenario=scenario_meta,
            )

            # Emit syslog for RIB add (notice)
            syslog_gen.emit(
                message=f"BGP route {prefix} added to RIB",
                severity="notice",
                subsystem="bgp",
                peer_ip="192.0.2.1",
                scenario=scenario_meta,
            )

            # Emit prefix-limit error (structured as misorigin)
            syslog_gen.prefix_limit_exceeded(
                peer_ip="192.0.2.1", limit=100, scenario=scenario_meta
            )

        elif action == "withdraw":
            scenario_meta = {
                "name": scenario_name,
                "attack_step": "withdrawal",
                "incident_id": incident_id,
            }

            # Emit BGP withdraw
            bgp_gen.emit_withdraw(
                prefix=prefix, withdrawn_by_as=65002, scenario=scenario_meta
            )

            # Emit syslog for withdrawal (info)
            syslog_gen.emit(
                message=f"BGP route {prefix} withdrawn after {entry.get('duration_seconds', 0)}s",
                severity="info",
                subsystem="bgp",
                peer_ip="192.0.2.1",
                scenario=scenario_meta,
            )

        elif action == "latency_spike":
            scenario_meta = {
                "name": scenario_name,
                "attack_step": "latency_spike",
                "incident_id": incident_id,
            }

            latency_gen.emit(
                source_router="R1",
                target_router="R2",
                latency_ms=150.0,
                jitter_ms=15.0,
                packet_loss_pct=0.1,
                scenario=scenario_meta,
            )

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
