"""
Telemetry mapping for the 'ROA poisoning' scenario.

Produces observable signals for control-plane attacks including
access anomalies, ROA manipulation, policy changes, and network impact.
"""

from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus, clock, scenario_name: str) -> None:
    """Register telemetry listeners for ROA poisoning scenario."""

    bgp_gen = BGPUpdateGenerator(
        clock=clock,
        event_bus=event_bus,
        scenario_name=scenario_name,
    )

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="R1",
        scenario_name=scenario_name,
    )

    def telemetry_listener(event: dict) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")

        if action == "baseline_rpki":
            # Normal RPKI state
            event_bus.publish({
                "event_type": "rpki.validation",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-validator", "observer": "validator"},
                "attributes": {
                    "prefix": entry["prefix"],
                    "origin_as": entry["origin_as"],
                    "validation_state": entry["rpki_state"],
                },
                "scenario": {"name": scenario_name, "attack_step": "baseline"}
            })

        elif action == "suspicious_login":
            # Access monitoring event
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
                "scenario": {"name": scenario_name, "attack_step": "initial_access"}
            })

        elif action == "roa_deleted":
            # ROA change event
            event_bus.publish({
                "event_type": "rpki.roa_change",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-ca", "observer": "ripe_ncc"},
                "attributes": {
                    "change_type": "removed",
                    "prefix": entry["prefix"],
                    "origin_as": entry["origin_as"],
                    "actor": entry["actor"],
                },
                "scenario": {"name": scenario_name, "attack_step": "roa_manipulation"}
            })

        elif action == "rpki_state_flip":
            # RPKI state change
            event_bus.publish({
                "event_type": "rpki.state_change",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-validator", "observer": "validator"},
                "attributes": {
                    "prefix": entry["prefix"],
                    "origin_as": entry["origin_as"],
                    "previous_state": entry["previous_state"],
                    "current_state": entry["current_state"],
                },
                "scenario": {"name": scenario_name, "attack_step": "rpki_impact"}
            })

        elif action == "policy_commit":
            # Policy change event
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
                "scenario": {"name": scenario_name, "attack_step": "policy_change"}
            })

            syslog_gen.configuration_change(
                user=entry["user"],
                change_summary=entry["message"],
                attack_step="policy_change",
            )

        elif action == "announce_with_roa":
            # Attacker announces with valid ROA
            bgp_gen.emit_update(
                prefix=entry["prefix"],
                as_path=[65004],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.10",
                attack_step="malicious_announce",
            )

            event_bus.publish({
                "event_type": "rpki.validation",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-validator", "observer": "validator"},
                "attributes": {
                    "prefix": entry["prefix"],
                    "origin_as": entry["attacker_as"],
                    "validation_state": entry["rpki_state"],
                },
                "scenario": {"name": scenario_name, "attack_step": "malicious_announce"}
            })

        elif action == "victim_route_rejected":
            # Victim's route rejected
            syslog_gen.emit(
                severity="error",
                message=f"Route {entry['prefix']} from AS{entry['victim_as']} rejected: {entry['reason']}",
                subsystem="bgp",
                attack_step="route_rejection",
            )

        elif action == "blackhole_community":
            # Blackhole community attached
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
                "scenario": {"name": scenario_name, "attack_step": "blackhole"}
            })

            syslog_gen.emit(
                severity="critical",
                message=f"Blackhole community {entry['community']} detected on {entry['prefix']}",
                subsystem="bgp",
                attack_step="blackhole",
            )

        elif action == "coordinated_flap":
            # Route flapping event
            event_bus.publish({
                "event_type": "bgp.flap_detected",
                "timestamp": clock.now(),
                "source": {"feed": "bgp-monitor", "observer": "collector"},
                "attributes": {
                    "prefixes": entry["prefixes"],
                    "flap_count": entry["flap_count"],
                    "pattern": "coordinated",
                },
                "scenario": {"name": scenario_name, "attack_step": "route_flapping"}
            })

        elif action == "roa_restored":
            # ROA restored
            event_bus.publish({
                "event_type": "rpki.roa_change",
                "timestamp": clock.now(),
                "source": {"feed": "rpki-ca", "observer": "ripe_ncc"},
                "attributes": {
                    "change_type": "added",
                    "prefix": entry["prefix"],
                    "origin_as": entry["origin_as"],
                    "actor": entry["actor"],
                },
                "scenario": {"name": scenario_name, "attack_step": "cleanup"}
            })

        elif action == "logout":
            # Logout event
            event_bus.publish({
                "event_type": "access.logout",
                "timestamp": clock.now(),
                "source": {"feed": "auth-system", "observer": "tacacs"},
                "attributes": {
                    "user": entry["user"],
                },
                "scenario": {"name": scenario_name, "attack_step": "disconnection"}
            })

    event_bus.subscribe(telemetry_listener)
