"""
Telemetry mapping for the 'subprefix intercept' scenario.

Produces observable signals for subprefix hijacking with forwarding.
"""


from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


def register(event_bus, clock, scenario_name: str) -> None:
    """Register telemetry listeners for subprefix interception."""

    bgp_gen = BGPUpdateGenerator(clock=clock, event_bus=event_bus, scenario_name=scenario_name)
    syslog_gen = RouterSyslogGenerator(clock=clock, event_bus=event_bus, router_name="R1", scenario_name=scenario_name)
    latency_gen = LatencyMetricsGenerator(clock=clock, event_bus=event_bus, scenario_name=scenario_name)

    def telemetry_listener(event: dict) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")
        if not action:
            return

        incident_id = f"{scenario_name}-{entry.get('subprefix', entry.get('prefix', 'unknown'))}"

        if action == "announce_subprefix":
            scenario_meta = {"name": scenario_name, "attack_step": "subprefix_announce", "incident_id": incident_id}

            bgp_gen.emit_update(
                prefix=entry["subprefix"],
                as_path=[65002, 65003],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.1",
                scenario=scenario_meta
            )

            syslog_gen.emit(
                severity="info",
                message=f"New route learned: {entry['subprefix']} via AS{entry['attacker_as']}",
                subsystem="bgp",
                scenario=scenario_meta
            )

        elif action == "traffic_intercept":
            scenario_meta = {"name": scenario_name, "attack_step": "intercept_active", "incident_id": incident_id}
            syslog_gen.emit(
                severity="info",
                message=f"Best path for {entry['subprefix']}: AS{entry['attacker_as']} (more-specific)",
                subsystem="routing",
                scenario=scenario_meta
            )

        elif action == "latency_spike":
            scenario_meta = {"name": scenario_name, "attack_step": "latency_anomaly", "incident_id": incident_id}
            latency_gen.emit(
                source_router="R1",
                target_router=entry["target"],
                latency_ms=entry["observed_ms"],
                jitter_ms=8.5,
                packet_loss_pct=0.05,
                scenario=scenario_meta
            )
            syslog_gen.emit(
                severity="warning",
                message=f"Latency to {entry['target']} increased from {entry['baseline_ms']}ms to {entry['observed_ms']}ms",
                subsystem="monitoring",
                scenario=scenario_meta
            )

        elif action == "withdraw":
            scenario_meta = {"name": scenario_name, "attack_step": "withdrawal", "incident_id": incident_id}
            bgp_gen.emit_withdraw(prefix=entry["subprefix"], withdrawn_by_as=entry["attacker_as"], scenario=scenario_meta)
            syslog_gen.emit(
                severity="info",
                message=f"Route withdrawn: {entry['subprefix']} from AS{entry['attacker_as']}",
                subsystem="bgp",
                scenario=scenario_meta
            )

        # Add other actions similarly...

    event_bus.subscribe(telemetry_listener)

