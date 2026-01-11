"""
Telemetry mapping for Playbook 1: RPKI Reconnaissance and ROA Creation.

Phase 1 of a multi-stage control-plane operation:
- RPKI reconnaissance for target prefix
- Legitimate ROA creation for our allocation
- Baseline documentation
- Waiting period to establish normality
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 1."""

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
    )

    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 1: RPKI Reconnaissance and ROA Creation",
        clock=clock,
        event_bus=event_bus,
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        attack_step = entry.get("attack_step", "unknown")
        prefix = (
            entry.get("prefix")
            or entry.get("target_prefix")
            or entry.get("our_prefix")
            or "unknown"
        )
        incident_id = f"{scenario_name}-{attack_step}-{prefix}"

        # === Emit BMP event for BGP announcements ===
        if action in {"baseline_announcement"}:
            bmp_gen.generate(entry)

        # === Emit syslog lines for realistic events ===
        if action in {"baseline_announcement", "roa_accepted", "validator_sync"}:
            msg = ""
            severity = "info"
            subsystem = "bgp"

            if action == "baseline_announcement":
                msg = f"BGP announcement observed: {prefix} origin AS{entry.get('origin_as')}"
                if entry.get("rpki_state"):
                    msg += f", RPKI {entry.get('rpki_state')}"
            elif action == "roa_accepted":
                msg = f"ROA request accepted for {prefix} AS{entry.get('origin_as')}"
                severity = "notice"
                subsystem = "rpki"
            elif action == "validator_sync":
                msg = (
                    f"Validator {entry.get('validator')} sees {prefix} "
                    f"origin AS{entry.get('origin_as')} -> {entry.get('rpki_state')}"
                )
                subsystem = "rpki"

            syslog_gen.emit(
                message=msg,
                severity=severity,
                subsystem=subsystem,
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === Phase transitions (internal, quiet) ===
        elif action in {
            "baseline_documented",
            "waiting_period_complete",
            "phase1_complete",
        }:
            event_bus.publish(
                {
                    "event_type": "internal.phase_event",
                    "timestamp": clock.now(),
                    "attributes": {
                        "action": action,
                        "attack_step": attack_step,
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === Training notes (SCENARIO lines) ===
        note = entry.get("note")
        if note:
            event_bus.publish(
                {
                    "event_type": "training.note",
                    "timestamp": clock.now(),
                    "line": f"SCENARIO: {note}",
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

    event_bus.subscribe(on_timeline_event)
