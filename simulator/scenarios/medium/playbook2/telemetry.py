"""
Telemetry mapping for Playbook 2: ROA Scope Expansion and Validation Mapping.

Control-plane attack escalation showing:
- Fraudulent ROA creation using compromised credentials (Action 2.1)
- Global RPKI validation deployment mapping (Action 2.2)
- Continuous ROA monitoring establishment (Action 2.3)

This is the critical pivot point where we transition from legitimate RPKI
participant to active attacker manipulating the validation infrastructure.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 2 scenario."""

    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 2: ROA Scope Expansion and Validation Mapping",
        clock=clock,
        event_bus=event_bus,
    )

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        """Map scenario timeline events to appropriate telemetry sources."""
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix", "unknown")
        attack_step = entry.get("attack_step", "unknown")
        incident_id = f"{scenario_name}-{prefix}-{attack_step}"

        # === PHASE 1 RECAP ===

        if action == "phase1_complete":
            event_bus.publish(
                {
                    "event_type": "internal.phase_transition",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "phase": "phase_1_complete",
                        "our_prefix": entry.get("our_prefix"),
                        "target_prefix": entry.get("target_prefix"),
                        "target_roa_status": entry.get("target_roa_status"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === ACTION 2.1: Fraudulent ROA Creation ===

        elif action == "credential_use":
            # Access event showing compromised credential use
            event_bus.publish(
                {
                    "event_type": "access.login",
                    "timestamp": clock.now(),
                    "source": {"feed": "auth-system", "observer": "rir-portal"},
                    "attributes": {
                        "user": entry.get("user"),
                        "source_ip": entry.get("source_ip"),
                        "system": entry.get("system"),
                        "suspicious": True,
                        "reason": "unusual_location",
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "fraudulent_roa_request":
            # RIR portal shows ROA creation request
            event_bus.publish(
                {
                    "event_type": "rpki.roa_creation",
                    "timestamp": clock.now(),
                    "source": {
                        "feed": "rir-portal",
                        "observer": entry.get("registry", "ARIN"),
                    },
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "max_length": entry.get("max_length"),
                        "registry": entry.get("registry"),
                        "actor": entry.get("actor"),
                        "cover_story": entry.get("cover_story"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

            syslog_gen.emit(
                message=f"ROA creation request for {prefix} (origin AS{entry.get('origin_as')}, maxLength /{entry.get('max_length')}) - FRAUDULENT",
                severity="critical",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "rir_validation_check":
            # RIR validation system checks the request
            event_bus.publish(
                {
                    "event_type": "rpki.validation",
                    "timestamp": clock.now(),
                    "source": {
                        "feed": "rir-validation",
                        "observer": entry.get("registry", "ARIN"),
                    },
                    "attributes": {
                        "prefix": prefix,
                        "requesting_as": entry.get("requesting_as"),
                        "validation_result": entry.get("validation_result"),
                        "registry": entry.get("registry"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "fraudulent_roa_accepted":
            # RIR accepts the fraudulent ROA
            syslog_gen.emit(
                message=f"ROA creation accepted for {prefix} by {entry.get('registry')} - ATTACK SUCCEEDING",
                severity="critical",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "fraudulent_roa_published":
            # Fraudulent ROA appears in repository
            event_bus.publish(
                {
                    "event_type": "rpki.roa_published",
                    "timestamp": clock.now(),
                    "source": {
                        "feed": "rpki-repository",
                        "observer": entry.get("trust_anchor", "arin"),
                    },
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "max_length": entry.get("max_length"),
                        "trust_anchor": entry.get("trust_anchor"),
                        "repository_url": entry.get("repository_url"),
                        "fraudulent": True,
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

            syslog_gen.emit(
                message=f"FRAUDULENT ROA published for {prefix} in {entry.get('trust_anchor')} repository",
                severity="critical",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "validator_sync":
            # Validators see the fraudulent ROA
            event_bus.publish(
                {
                    "event_type": "rpki.validator_sync",
                    "timestamp": clock.now(),
                    "source": {
                        "feed": "rpki-validator",
                        "observer": entry.get("validator", "routinator"),
                    },
                    "attributes": {
                        "prefix": prefix,
                        "validator": entry.get("validator"),
                        "rpki_state": entry.get("rpki_state"),
                        "origin_as": entry.get("origin_as"),
                        "sync_type": "repository_poll",
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "conflicting_roas_detected":
            # Multiple ROAs for same prefix detected
            event_bus.publish(
                {
                    "event_type": "rpki.conflict_detected",
                    "timestamp": clock.now(),
                    "source": {
                        "feed": "rpki-validator",
                        "observer": "conflict-monitor",
                    },
                    "attributes": {
                        "prefix": prefix,
                        "roa_count": entry.get("roa_count"),
                        "origins": entry.get("origins", []),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === ACTION 2.2: Validation Deployment Mapping ===

        elif action == "validation_test_start":
            event_bus.publish(
                {
                    "event_type": "internal.test_phase",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {"test_type": entry.get("test_type")},
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "test_announcement":
            # Test BGP announcement to map validation deployment
            test_prefix = entry.get("prefix")
            bmp_event = {
                "prefix": test_prefix,
                "as_path": [65001, entry.get("origin_as")],
                "origin_as": entry.get("origin_as"),
                "next_hop": "198.51.100.254",
                "peer_ip": "198.51.100.1",
                "peer_as": 65001,
                "peer_bgp_id": "198.51.100.1",
                "rpki_state": entry.get("expected_rpki_state"),
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            }
            bmp_gen.generate(bmp_event)

            # Log peer response
            syslog_gen.emit(
                message=f"Validation test {entry.get('region')}: Announcement {test_prefix} AS{entry.get('origin_as')} - peer {entry.get('peer_response')}",
                severity="notice",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "validation_withdrawal":
            # Withdraw test announcement
            test_prefix = entry.get("prefix")
            bmp_event = {
                "prefix": test_prefix,
                "as_path": [65001, entry.get("origin_as")],
                "origin_as": entry.get("origin_as"),
                "next_hop": "198.51.100.254",
                "peer_ip": "198.51.100.1",
                "peer_as": 65001,
                "peer_bgp_id": "198.51.100.1",
                "is_withdraw": True,
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            }
            bmp_gen.generate(bmp_event)

        elif action == "validation_map_complete":
            # Validation deployment mapping complete
            event_bus.publish(
                {
                    "event_type": "internal.analysis_complete",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "regions": entry.get("regions", {}),
                        "target_region": entry.get("target_region"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "roa_visibility_check":
            # Check fraudulent ROA visibility across validators
            event_bus.publish(
                {
                    "event_type": "rpki.visibility_check",
                    "timestamp": clock.now(),
                    "source": {"feed": "rpki-validator", "observer": "multi-validator"},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry.get("origin_as"),
                        "validators_checked": entry.get("validators_checked", []),
                        "visible_count": entry.get("visible_count"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === ACTION 2.3: ROA Monitoring ===

        elif action == "monitoring_deployed":
            event_bus.publish(
                {
                    "event_type": "internal.monitoring_deployed",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "target_prefix": entry.get("target_prefix"),
                        "check_interval": entry.get("check_interval"),
                        "alert_on": entry.get("alert_on", []),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "monitoring_baseline":
            event_bus.publish(
                {
                    "event_type": "internal.monitoring_baseline",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "prefix": prefix,
                        "roa_count": entry.get("roa_count"),
                        "our_roa_present": entry.get("our_roa_present"),
                        "victim_roa_count": entry.get("victim_roa_count"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "stability_check":
            event_bus.publish(
                {
                    "event_type": "internal.stability_check",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "prefix": prefix,
                        "hours_stable": entry.get("hours_stable"),
                        "our_roa_present": entry.get("our_roa_present"),
                        "no_alerts": entry.get("no_alerts"),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === PHASE 2 COMPLETE ===

        elif action == "phase2_complete":
            event_bus.publish(
                {
                    "event_type": "internal.phase_complete",
                    "timestamp": clock.now(),
                    "source": {"feed": "operator", "observer": "attack-team"},
                    "attributes": {
                        "phase": "phase_2",
                        "fraudulent_roa_status": entry.get("fraudulent_roa_status"),
                        "validation_map": entry.get("validation_map"),
                        "monitoring_status": entry.get("monitoring_status"),
                        "target_region": entry.get("target_region"),
                        "ready_for": "phase_3_hijack_execution",
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
