"""
Telemetry mapping for the Subprefix Intercept scenario.

Produces structured BGP, syslog, and latency telemetry for
subprefix hijacking with traffic forwarding, fully Wazuh-ingestible.
"""

from typing import Any
from simulator.engine.event_bus import EventBus
from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


def register(event_bus: EventBus, clock: Any, scenario_name: str)-> None:
    bgp_gen = BGPUpdateGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )
    syslog_gen = RouterSyslogGenerator(
        clock=clock, event_bus=event_bus, router_name="R1", scenario_name=scenario_name
    )
    latency_gen = LatencyMetricsGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )

    def on_timeline_event(event: dict[str, Any])-> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix") or entry.get("subprefix")
        incident_id = (
            f"{scenario_name}-{prefix}" if prefix else f"{scenario_name}-unknown"
        )

        if action == "baseline":
            bgp_gen.emit_update(
                prefix=prefix,
                as_path=[65001],
                origin_as=entry["victim_as"],
                next_hop="192.0.2.10",
                scenario={
                    "name": scenario_name,
                    "attack_step": "baseline",
                    "incident_id": incident_id,
                },
            )

        elif action == "announce_subprefix":
            bgp_gen.emit_update(
                prefix=entry["subprefix"],
                as_path=[65002, entry["attacker_as"]],
                origin_as=entry["attacker_as"],
                next_hop="198.51.100.1",
                scenario={
                    "name": scenario_name,
                    "attack_step": "subprefix_announce",
                    "incident_id": incident_id,
                },
            )
            syslog_gen.emit(
                message=f"New route learned: {entry['subprefix']} via AS{entry['attacker_as']}",
                severity="info",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "subprefix_announce",
                    "incident_id": incident_id,
                },
            )

        elif action == "traffic_intercept":
            syslog_gen.emit(
                message=f"Best path for {entry['subprefix']}: AS{entry['attacker_as']} (more-specific)",
                severity="info",
                subsystem="routing",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "intercept_active",
                    "incident_id": incident_id,
                },
            )

        elif action == "latency_spike":
            latency_gen.emit(
                source_router="R1",
                target_router=entry["target"],
                latency_ms=entry["observed_ms"],
                jitter_ms=8.5,
                packet_loss_pct=0.05,
                scenario={
                    "name": scenario_name,
                    "attack_step": "latency_anomaly",
                    "incident_id": incident_id,
                },
            )
            syslog_gen.emit(
                message=f"Latency to {entry['target']} increased from {entry['baseline_ms']}ms to {entry['observed_ms']}ms",
                severity="warning",
                subsystem="monitoring",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "latency_anomaly",
                    "incident_id": incident_id,
                },
            )

        elif action == "maintain":
            syslog_gen.emit(
                message="BGP session stable, all routes converged",
                severity="debug",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "maintain",
                    "incident_id": incident_id,
                },
            )

        elif action == "withdraw":
            bgp_gen.emit_withdraw(
                prefix=entry["subprefix"],
                withdrawn_by_as=entry["attacker_as"],
                scenario={
                    "name": scenario_name,
                    "attack_step": "withdrawal",
                    "incident_id": incident_id,
                },
            )
            syslog_gen.emit(
                message=f"Route withdrawn: {entry['subprefix']} from AS{entry['attacker_as']}",
                severity="info",
                subsystem="bgp",
                peer_ip=None,
                scenario={
                    "name": scenario_name,
                    "attack_step": "withdrawal",
                    "incident_id": incident_id,
                },
            )

        elif action == "latency_normal":
            latency_gen.emit(
                source_router="R1",
                target_router=entry["target"],
                latency_ms=entry["observed_ms"],
                jitter_ms=2.1,
                packet_loss_pct=0.0,
                scenario={
                    "name": scenario_name,
                    "attack_step": "restoration",
                    "incident_id": incident_id,
                },
            )

    event_bus.subscribe(on_timeline_event)
