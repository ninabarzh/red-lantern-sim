"""
Telemetry mapping for the ROA Poisoning scenario.

Structured telemetry for control-plane attacks including
ROA manipulation, policy changes, RPKI state flips, and access events.
All events emit fully Wazuh-ingestible JSON.
"""

from typing import Any

from simulator.engine.event_bus import EventBus
from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: Any, scenario_name: str) -> None:
    bgp_gen = BGPUpdateGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )
    syslog_gen = RouterSyslogGenerator(
        clock=clock, event_bus=event_bus, router_name="R1", scenario_name=scenario_name
    )

    def on_timeline_event(event: dict[str, Any]) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")
        prefix = entry.get("prefix") or entry.get("subprefix")
        incident_id = (
            f"{scenario_name}-{prefix}" if prefix else f"{scenario_name}-unknown"
        )

        if action == "baseline_rpki":
            event_bus.publish(
                {
                    "event_type": "rpki.validation",
                    "timestamp": clock.now(),
                    "source": {"feed": "rpki-validator", "observer": "validator"},
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": entry["origin_as"],
                        "validation_state": entry["rpki_state"],
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": "baseline",
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "suspicious_login":
            event_bus.publish(
                {
                    "event_type": "access.login",
                    "timestamp": clock.now(),
                    "source": {"feed": "auth-system", "observer": "tacacs"},
                    "attributes": {
                        "user": entry["user"],
                        "source_ip": entry["source_ip"],
                        "location": entry["location"],
                        "system": entry["system"],
                        "suspicious": True,
                        "reason": "unusual_location",
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": "initial_access",
                        "incident_id": incident_id,
                    },
                }
            )

        elif action == "roa_deleted":
            syslog_gen.emit(
                message=f"ROA for {prefix} removed by {entry['actor']}",
                severity="warning",
                subsystem="rpki",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "roa_manipulation",
                    "incident_id": incident_id,
                },
            )

        elif action == "rpki_state_flip":
            syslog_gen.emit(
                message=f"RPKI state for {prefix} flipped from {entry['previous_state']} to {entry['current_state']}",
                severity="notice",
                subsystem="rpki",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "rpki_impact",
                    "incident_id": incident_id,
                },
            )

        elif action == "policy_commit":
            syslog_gen.configuration_change(
                user=entry["user"],
                change_summary=entry["message"],
                attack_step="policy_change",
            )

        elif action == "announce_with_roa":
            bgp_gen.emit_update(
                prefix=prefix,
                as_path=[65004],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.10",
                scenario={
                    "name": scenario_name,
                    "attack_step": "malicious_announce",
                    "incident_id": incident_id,
                },
            )

        elif action == "victim_route_rejected":
            syslog_gen.emit(
                message=f"Route {prefix} from AS{entry['victim_as']} rejected: {entry['reason']}",
                severity="error",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "route_rejection",
                    "incident_id": incident_id,
                },
            )

        elif action == "blackhole_community":
            syslog_gen.emit(
                message=f"Blackhole community {entry['community']} detected on {prefix}",
                severity="critical",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "blackhole",
                    "incident_id": incident_id,
                },
            )

        elif action == "coordinated_flap":
            syslog_gen.emit(
                message=f"Coordinated flapping on prefixes: {', '.join(entry['prefixes'])}, flap count: {entry['flap_count']}",
                severity="warning",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "route_flapping",
                    "incident_id": incident_id,
                },
            )

        elif action == "roa_restored":
            syslog_gen.emit(
                message=f"ROA for {prefix} restored by {entry['actor']}",
                severity="notice",
                subsystem="rpki",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "cleanup",
                    "incident_id": incident_id,
                },
            )

        elif action == "logout":
            event_bus.publish(
                {
                    "event_type": "access.logout",
                    "timestamp": clock.now(),
                    "source": {"feed": "auth-system", "observer": "tacacs"},
                    "attributes": {
                        "user": entry["user"],
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": "disconnection",
                        "incident_id": incident_id,
                    },
                }
            )

    event_bus.subscribe(on_timeline_event)
