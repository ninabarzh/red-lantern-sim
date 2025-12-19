"""
Telemetry mapping for the 'ROA poisoning' scenario.

Produces observable signals for control-plane attacks including
access anomalies, ROA manipulation, policy changes, and network impact.
"""

from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus, clock, scenario_name: str) -> None:
    """Register telemetry listeners for ROA poisoning scenario."""

    bgp_gen = BGPUpdateGenerator(clock=clock, event_bus=event_bus, scenario_name=scenario_name)
    syslog_gen = RouterSyslogGenerator(clock=clock, event_bus=event_bus, router_name="R1", scenario_name=scenario_name)

    def telemetry_listener(event: dict) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")
        if not action:
            return

        incident_id = f"{scenario_name}-{entry.get('prefix', 'unknown')}"

        if action == "baseline_rpki":
            scenario_meta = {"name": scenario_name, "attack_step": "baseline", "incident_id": incident_id}
            event_bus.publish({
                "event_type": "rpki.validation",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-validator", "observer": "validator"},
                "attributes": {
                    "prefix": entry["prefix"],
                    "origin_as": entry["origin_as"],
                    "validation_state": entry["rpki_state"],
                },
                "scenario": scenario_meta
            })

        elif action == "suspicious_login":
            scenario_meta = {"name": scenario_name, "attack_step": "initial_access", "incident_id": incident_id}
            event_bus.publish({
                "event_type": "access.login",
                "timestamp": clock.now(),
                "source": {"feed": "auth-system", "observer": "tacacs"},
                "attributes": {
                    "user": entry["user"],
                    "source_ip": entry["source_ip"],
                    "location": entry["location"],
                    "system": entry["system"],
                    "suspicious": True,
                    "reason": "unusual_location"
                },
                "scenario": scenario_meta
            })

        elif action == "policy_commit":
            scenario_meta = {"name": scenario_name, "attack_step": "policy_change", "incident_id": incident_id}
            event_bus.publish({
                "event_type": "config.commit",
                "timestamp": clock.now(),
                "source": {"feed": "git-repo", "observer": "policy_system"},
                "attributes": {
                    "user": entry["user"],
                    "commit_hash": entry["commit_hash"],
                    "message": entry["message"],
                    "files_changed": entry["files_changed"],
                },
                "scenario": scenario_meta
            })

            syslog_gen.emit(
                message=f"Configuration change by {entry['user']}: {entry['message']}",
                severity="notice",
                subsystem="config",
                scenario=scenario_meta
            )

        elif action == "victim_route_rejected":
            scenario_meta = {"name": scenario_name, "attack_step": "route_rejection", "incident_id": incident_id}
            syslog_gen.emit(
                severity="error",
                message=f"Route {entry['prefix']} from AS{entry['victim_as']} rejected: {entry['reason']}",
                subsystem="bgp",
                scenario=scenario_meta
            )

        elif action == "blackhole_community":
            scenario_meta = {"name": scenario_name, "attack_step": "blackhole", "incident_id": incident_id}
            event_bus.publish({
                "event_type": "bgp.community_detected",
                "timestamp": clock.now(),
                "source": {"feed": "bgp-monitor", "observer": "collector"},
                "attributes": {
                    "prefix": entry["prefix"],
                    "community": entry["community"],
                    "origin_as": entry["attacker_as"],
                    "community_name": "blackhole",
                },
                "scenario": scenario_meta
            })

            syslog_gen.emit(
                severity="critical",
                message=f"Blackhole community {entry['community']} detected on {entry['prefix']}",
                subsystem="bgp",
                scenario=scenario_meta
            )

        # Add other actions similarly...

    event_bus.subscribe(telemetry_listener)
