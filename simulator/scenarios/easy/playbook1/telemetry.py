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

# from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 1."""

    # bmp_gen = BMPTelemetryGenerator(
    #     scenario_id=scenario_name,
    #     scenario_name="Playbook 1: RPKI Reconnaissance and ROA Creation",
    #     clock=clock,
    #     event_bus=event_bus,
    # )

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
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

        # === BASELINE ANNOUNCEMENTS ===
        if action == "baseline_announcement":
            syslog_gen.emit(
                message=f"BGP announcement observed: {prefix} origin AS{entry.get('origin_as')}",
                severity="info",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === ACTION 1.1: RPKI Reconnaissance ===
        elif action == "rpki_query":
            event_bus.publish(
                {
                    "event_type": "rpki.query",
                    "timestamp": clock.now(),
                    "source": {"observer": entry.get("query_source")},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "query_type": entry.get("query_type"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "rpki_validation_result":
            event_bus.publish(
                {
                    "event_type": "rpki.validation",
                    "timestamp": clock.now(),
                    "source": {"observer": entry.get("validator", "routinator")},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "validation_state": entry.get("rpki_state"),
                        "roa_exists": entry.get("roa_exists"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "validator_query":
            event_bus.publish(
                {
                    "event_type": "rpki.query",
                    "timestamp": clock.now(),
                    "source": {"observer": entry.get("validator")},
                    "attributes": {
                        "prefix": prefix,
                        "query_type": "local_validator_check",
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "whois_query":
            event_bus.publish(
                {
                    "event_type": "registry.whois",
                    "timestamp": clock.now(),
                    "source": {"observer": "whois-client"},
                    "attributes": {
                        "prefix": prefix,
                        "allocated_to": entry.get("allocated_to"),
                        "registry": entry.get("registry"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === ACTION 1.2: Legitimate ROA Creation ===
        elif action == "roa_creation_request":
            event_bus.publish(
                {
                    "event_type": "rpki.roa_creation",
                    "timestamp": clock.now(),
                    "source": {"observer": "rpki-portal"},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "max_length": entry.get("max_length"),
                        "registry": entry.get("registry"),
                        "actor": entry.get("actor"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "roa_accepted":
            syslog_gen.emit(
                message=f"ROA request accepted for {prefix} AS{entry.get('origin_as')}",
                severity="notice",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "roa_published":
            event_bus.publish(
                {
                    "event_type": "rpki.roa_published",
                    "timestamp": clock.now(),
                    "source": {"observer": "rpki-repository"},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "trust_anchor": entry.get("trust_anchor"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "validator_sync":
            syslog_gen.emit(
                message=f"Validator {entry.get('validator')} sees prefix {prefix} as {entry.get('rpki_state')}",
                severity="info",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === ACTION 1.3: Baseline Documentation ===
        elif action == "baseline_documented":
            event_bus.publish(
                {
                    "event_type": "internal.documentation",
                    "timestamp": clock.now(),
                    "source": {"observer": "operator"},
                    "attributes": {
                        "target_prefix": entry.get("target_prefix"),
                        "target_roa_status": entry.get("target_roa_status"),
                        "our_roa_status": entry.get("our_roa_status"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === PHASE TRANSITIONS ===
        elif action == "waiting_period_complete":
            event_bus.publish(
                {
                    "event_type": "internal.phase_transition",
                    "timestamp": clock.now(),
                    "source": {"observer": "operator"},
                    "attributes": {
                        "phase": "phase_1_wait_complete",
                        "days_elapsed": entry.get("days_elapsed"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "phase1_complete":
            event_bus.publish(
                {
                    "event_type": "internal.phase_complete",
                    "timestamp": clock.now(),
                    "source": {"observer": "operator"},
                    "attributes": {"phase": "phase_1"},
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
