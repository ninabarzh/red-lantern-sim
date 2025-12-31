"""
Telemetry mapping for Playbook 3: Prefix Hijacking with RPKI Validation Cover.

Control-plane attack execution showing:
- Sub-prefix hijack announcement that validates as RPKI VALID (Action 3.1)
- Traffic interception verification (Action 3.2)
- Service forwarding to maintain availability (Action 3.3)
- Operational monitoring during active hijack (Action 3.4)
- Controlled withdrawal (Action 3.5)

This is the payoff: validators endorse our hijack as legitimate because we
poisoned the validation infrastructure in phases 1-2.
"""

from typing import Any
from simulator.engine.event_bus import EventBus
from simulator.engine.clock import SimulationClock
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 3 scenario."""

    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 3: Prefix Hijacking with RPKI Validation Cover",
        clock=clock,
        event_bus=event_bus
    )

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        """Map scenario timeline events to appropriate telemetry sources."""
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix", entry.get("hijacked_prefix", "unknown"))
        attack_step = entry.get("attack_step", "unknown")
        incident_id = f"{scenario_name}-{prefix}-{attack_step}"

        # === PHASE 2 RECAP ===

        if action == "phase2_complete":
            event_bus.publish({
                "event_type": "internal.phase_transition",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "phase": "phase_2_complete",
                    "fraudulent_roa_prefix": entry.get("fraudulent_roa_prefix"),
                    "target_region": entry.get("target_region")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === ACTION 3.1: Hijack Announcement ===

        elif action == "hijack_announcement":
            # BMP RouteMonitoring message showing the hijack
            bmp_event = {
                "prefix": prefix,
                "as_path": entry.get("as_path", []),
                "origin_as": entry.get("origin_as"),
                "next_hop": entry.get("next_hop"),
                "peer_ip": entry.get("peer_ip"),
                "peer_as": entry.get("peer_as"),
                "peer_bgp_id": entry.get("peer_bgp_id"),
                "communities": entry.get("communities", []),
                "rpki_state": entry.get("rpki_state"),
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            }
            bmp_gen.generate(bmp_event)

            # Realistic syslog message (no "HIJACK" label)
            syslog_gen.emit(
                message=f"BGP announcement: {prefix} from AS{entry.get('origin_as')}, RPKI validation: {entry.get('rpki_state')}",
                severity="info",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            )

        elif action == "announcement_propagation":
            event_bus.publish({
                "event_type": "bgp.propagation",
                "timestamp": clock.now(),
                "source": {"feed": "bgp-monitor", "observer": "route-collector"},
                "attributes": {
                    "prefix": prefix,
                    "propagation_status": entry.get("propagation_status"),
                    "peers_accepting": entry.get("peers_accepting"),
                    "peers_total": entry.get("peers_total")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "rpki_validation_check":
            # RPKI validation returns VALID - control-plane attack succeeding
            event_bus.publish({
                "event_type": "rpki.validation",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-validator", "observer": entry.get("validator", "routinator")},
                "attributes": {
                    "prefix": prefix,
                    "origin_as": entry.get("origin_as"),
                    "validation_state": entry.get("validation_result"),
                    "validator": entry.get("validator")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

            # Realistic syslog message (no "FRAUDULENT" label)
            syslog_gen.emit(
                message=f"RPKI validation: {prefix} AS{entry.get('origin_as')} -> {entry.get('validation_result')} ({entry.get('validator')})",
                severity="info",
                subsystem="rpki",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            )

        # === ACTION 3.2: Traffic Interception Verification ===

        elif action == "traffic_interception_test":
            event_bus.publish({
                "event_type": "network.traceroute",
                "timestamp": clock.now(),
                "source": {"feed": "test-infrastructure", "observer": entry.get("test_source")},
                "attributes": {
                    "destination": entry.get("destination"),
                    "via_as": entry.get("via_as"),
                    "result": entry.get("result"),
                    "test_source": entry.get("test_source")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "interception_summary":
            event_bus.publish({
                "event_type": "internal.analysis",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "regions_intercepted": entry.get("regions_intercepted", []),
                    "regions_not_intercepted": entry.get("regions_not_intercepted", []),
                    "interception_percentage": entry.get("interception_percentage")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === ACTION 3.3: Service Forwarding ===

        elif action == "forwarding_established":
            syslog_gen.emit(
                message=f"Traffic forwarding established for {entry.get('hijacked_prefix')} -> {entry.get('forward_to')} (method: {entry.get('forward_method')})",
                severity="warning",
                subsystem="routing",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            )

        elif action == "service_continuity_verified":
            event_bus.publish({
                "event_type": "internal.service_check",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "hijacked_prefix": entry.get("hijacked_prefix"),
                    "services_functional": entry.get("services_functional"),
                    "added_latency_ms": entry.get("added_latency_ms"),
                    "packet_loss_increase": entry.get("packet_loss_increase")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "victim_traffic_analysis":
            # Victim's perspective - HIGH DETECTION RISK
            event_bus.publish({
                "event_type": "netflow.analysis",
                "timestamp": clock.now(),
                "source": {"feed": "netflow-collector", "observer": "victim-network"},
                "attributes": {
                    "prefix": entry.get("victim_prefix"),
                    "traffic_volume_drop_pct": entry.get("traffic_volume_drop_pct"),
                    "source_ip_changes": entry.get("source_ip_changes"),
                    "source_as_changed_to": entry.get("source_as_changed_to")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === ACTION 3.4: Operational Monitoring ===

        elif action == "hijack_monitoring_start":
            event_bus.publish({
                "event_type": "internal.monitoring_start",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "monitor_roa_status": entry.get("monitor_roa_status"),
                    "monitor_bgp_stability": entry.get("monitor_bgp_stability"),
                    "monitor_abuse_complaints": entry.get("monitor_abuse_complaints"),
                    "check_interval": entry.get("check_interval")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "monitoring_check":
            event_bus.publish({
                "event_type": "internal.monitoring_status",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "roa_status": entry.get("roa_status"),
                    "bgp_announcement": entry.get("bgp_announcement"),
                    "abuse_complaints": entry.get("abuse_complaints"),
                    "public_monitoring_alerts": entry.get("public_monitoring_alerts"),
                    "victim_investigation": entry.get("victim_investigation", False)
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "objective_achieved":
            event_bus.publish({
                "event_type": "internal.objective_complete",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "duration_minutes": entry.get("duration_minutes"),
                    "traffic_intercepted_gb": entry.get("traffic_intercepted_gb"),
                    "services_monitored": entry.get("services_monitored")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === ACTION 3.5: Controlled Withdrawal ===

        elif action == "withdrawal_decision":
            event_bus.publish({
                "event_type": "internal.withdrawal_decision",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "reason": entry.get("reason"),
                    "withdrawal_timing": entry.get("withdrawal_timing"),
                    "cover_story": entry.get("cover_story")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "withdrawal_announcement":
            # BGP WITHDRAW message
            bmp_event = {
                "prefix": prefix,
                "as_path": entry.get("as_path", [65001, entry.get("origin_as")]),
                "origin_as": entry.get("origin_as"),
                "next_hop": "198.51.100.254",
                "peer_ip": "198.51.100.1",
                "peer_as": 65001,
                "peer_bgp_id": "198.51.100.1",
                "is_withdraw": True,
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            }
            bmp_gen.generate(bmp_event)

            # Realistic syslog message (no "hijack ending" label)
            syslog_gen.emit(
                message=f"BGP withdrawal: {prefix} from AS{entry.get('origin_as')}",
                severity="notice",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            )

        elif action == "withdrawal_propagation":
            event_bus.publish({
                "event_type": "bgp.withdrawal_complete",
                "timestamp": clock.now(),
                "source": {"feed": "bgp-monitor", "observer": "route-collector"},
                "attributes": {
                    "prefix": prefix,
                    "withdrawal_status": entry.get("withdrawal_status"),
                    "peers_removed": entry.get("peers_removed")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "traffic_reconvergence":
            event_bus.publish({
                "event_type": "bgp.reconvergence",
                "timestamp": clock.now(),
                "source": {"feed": "bgp-monitor", "observer": "route-collector"},
                "attributes": {
                    "prefix": prefix,
                    "legitimate_path_restored": entry.get("legitimate_path_restored"),
                    "via_as": entry.get("via_as"),
                    "reconvergence_time_seconds": entry.get("reconvergence_time_seconds")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "victim_service_restored":
            event_bus.publish({
                "event_type": "netflow.normal",
                "timestamp": clock.now(),
                "source": {"feed": "netflow-collector", "observer": "victim-network"},
                "attributes": {
                    "prefix": prefix,
                    "traffic_volume_normal": entry.get("traffic_volume_normal"),
                    "source_as_normal": entry.get("source_as_normal")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === Post-Operation Assessment ===

        elif action == "hijack_evidence_assessment":
            event_bus.publish({
                "event_type": "internal.evidence_assessment",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "bgp_historical_data": entry.get("bgp_historical_data"),
                    "netflow_historical_data": entry.get("netflow_historical_data"),
                    "rpki_audit_trail": entry.get("rpki_audit_trail"),
                    "fraudulent_roa_status": entry.get("fraudulent_roa_status")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        elif action == "cleanup_decision":
            event_bus.publish({
                "event_type": "internal.cleanup_plan",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "fraudulent_roa_action": entry.get("fraudulent_roa_action"),
                    "cover_story": entry.get("cover_story"),
                    "revocation_timing": entry.get("revocation_timing")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

        # === PHASE 3 COMPLETE ===

        elif action == "phase3_complete":
            event_bus.publish({
                "event_type": "internal.phase_complete",
                "timestamp": clock.now(),
                "source": {"feed": "operator", "observer": "attack-team"},
                "attributes": {
                    "phase": "phase_3",
                    "hijack_duration_minutes": entry.get("hijack_duration_minutes"),
                    "traffic_intercepted": entry.get("traffic_intercepted"),
                    "rpki_validation_status": entry.get("rpki_validation_status"),
                    "control_plane_attack_confirmed": entry.get("control_plane_attack_confirmed"),
                    "detection_during_operation": entry.get("detection_during_operation"),
                    "withdrawal_clean": entry.get("withdrawal_clean")
                },
                "scenario": {
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id
                }
            })

    # Subscribe to all timeline events
    event_bus.subscribe(on_timeline_event)
