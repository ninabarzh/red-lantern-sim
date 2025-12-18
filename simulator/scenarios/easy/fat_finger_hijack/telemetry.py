"""
Telemetry mapping for the 'fat finger hijack' scenario.

This module translates scenario timeline entries into
observable telemetry that a SOC or NOC would realistically see.
"""

from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus, clock, scenario_name: str) -> None:
    """
    Register telemetry listeners for this scenario.

    Called by the CLI after scenario loading.
    """

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

        if action == "announce":
            # --- Informational, boring, realistic ---
            syslog_gen.emit(
                severity="info",
                message=f"BGP route {entry['prefix']} added to RIB",
                subsystem="bgp",
                peer_ip="192.0.2.1",
                attack_step="misorigin",
            )

            # --- First propagation path ---
            bgp_gen.emit_update(
                prefix=entry["prefix"],
                as_path=[entry["attacker_as"]],
                origin_as=entry["attacker_as"],
                next_hop="192.0.2.1",
                attack_step="misorigin",
            )

            # --- Second peer: partial propagation ---
            bgp_gen.emit_update(
                prefix=entry["prefix"],
                as_path=[65003, entry["attacker_as"]],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.1",
                attack_step="misorigin",
            )

            # --- Mild control-plane noise ---
            syslog_gen.bgp_session_reset(
                peer_ip="192.0.2.1",
                reason="BGP table change detected",
                attack_step="misorigin",
            )

        elif action == "withdraw":
            # --- Withdraw BGP route ---
            bgp_gen.emit_withdraw(
                prefix=entry["prefix"],
                withdrawn_by_as=entry["attacker_as"],
                attack_step="withdrawal",
            )

            # --- Informational withdrawal with duration ---
            duration = entry.get("duration_seconds")
            suffix = f" after {duration}s" if duration else ""
            syslog_gen.emit(
                severity="info",
                message=f"BGP route {entry['prefix']} withdrawn{suffix}",
                subsystem="bgp",
                peer_ip="192.0.2.1",
                attack_step="withdrawal",
            )

            # --- Error for prefix limit exceeded remains ---
            syslog_gen.prefix_limit_exceeded(
                peer_ip="192.0.2.1",
                limit=100,
                attack_step="withdrawal",
            )

    event_bus.subscribe(telemetry_listener)
