"""
Telemetry mapping for the 'subprefix intercept' scenario.

Produces observable signals for subprefix hijacking with forwarding.
"""


from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


def register(event_bus, clock, scenario_name: str) -> None:
    """Register telemetry listeners for subprefix interception."""

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

    latency_gen = LatencyMetricsGenerator(
        clock=clock,
        event_bus=event_bus,
        scenario_name=scenario_name,
    )

    def telemetry_listener(event: dict) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")

        if action == "baseline":
            bgp_gen.emit_update(
                prefix=entry["prefix"],
                as_path=[65001],
                origin_as=entry["victim_as"],
                next_hop="192.0.2.10",
                attack_step="baseline",
            )

        elif action == "announce_subprefix":
            bgp_gen.emit_update(
                prefix=entry["subprefix"],
                as_path=[65002, 65003],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.1",
                attack_step="subprefix_announce",
            )

            syslog_gen.emit(
                severity="info",
                message=f"New route learned: {entry['subprefix']} via AS{entry['attacker_as']}",
                subsystem="bgp",
                attack_step="subprefix_announce",
            )

        elif action == "traffic_intercept":
            syslog_gen.emit(
                severity="info",
                message=f"Best path for {entry['subprefix']}: AS{entry['attacker_as']} (more-specific)",
                subsystem="routing",
                attack_step="intercept_active",
            )

        elif action == "latency_spike":
            latency_gen.emit(
                source_router="R1",
                target_router=entry["target"],
                latency_ms=entry["observed_ms"],
                jitter_ms=8.5,
                packet_loss_pct=0.05,
                attack_step="latency_anomaly",
            )

            syslog_gen.emit(
                severity="warning",
                message=f"Latency to {entry['target']} increased from {entry['baseline_ms']}ms to {entry['observed_ms']}ms",
                subsystem="monitoring",
                attack_step="latency_anomaly",
            )

        elif action == "maintain":
            syslog_gen.emit(
                severity="debug",
                message="BGP session stable, all routes converged",
                subsystem="bgp",
                attack_step="maintain",
            )

        elif action == "withdraw":
            bgp_gen.emit_withdraw(
                prefix=entry["subprefix"],
                withdrawn_by_as=entry["attacker_as"],
                attack_step="withdrawal",
            )

            syslog_gen.emit(
                severity="info",
                message=f"Route withdrawn: {entry['subprefix']} from AS{entry['attacker_as']}",
                subsystem="bgp",
                attack_step="withdrawal",
            )

        elif action == "latency_normal":
            latency_gen.emit(
                source_router="R1",
                target_router=entry["target"],
                latency_ms=entry["observed_ms"],
                jitter_ms=2.1,
                packet_loss_pct=0.0,
                attack_step="restoration",
            )

    event_bus.subscribe(telemetry_listener)
