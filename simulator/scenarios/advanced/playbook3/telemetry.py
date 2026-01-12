"""Telemetry mapping for Playbook 3: Prefix Hijacking with RPKI Validation Cover."""

import random
from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.rpki_generator import RPKIGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 3."""

    bmp_gen = BMPTelemetryGenerator(
        scenario_id="playbook3_hijack_execution",
        scenario_name=scenario_name,
        clock=clock,
        event_bus=event_bus,
        collector_id="bmp-collector-01",
    )

    router_syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
    )

    rpki_gen = RPKIGenerator(
        clock=clock, event_bus=event_bus, scenario_name=scenario_name
    )

    def jitter(max_seconds: float = 60.0) -> float:
        """Return random jitter up to max_seconds."""
        return random.uniform(0, max_seconds)

    def on_event(event: dict[str, Any]) -> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix", "unknown")
        attack_step = entry.get("attack_step", "unknown")
        incident_id = f"{scenario_name}-{prefix}-{attack_step}"

        scenario = {
            "name": scenario_name,
            "attack_step": attack_step,
            "incident_id": incident_id,
        }

        # === PHASE TRANSITIONS ===
        if action == "phase2_complete":
            # Internal documentation - will be filtered
            event_bus.publish(
                {
                    "event_type": "internal.documentation",
                    "timestamp": clock.now(),
                    "attributes": {
                        "action": action,
                        "attack_step": attack_step,
                        "fraudulent_roa_prefix": entry.get("fraudulent_roa_prefix"),
                        "fraudulent_roa_origin": entry.get("fraudulent_roa_origin"),
                    },
                    "scenario": scenario,
                }
            )
            return

        elif action == "phase3_complete":
            # Internal phase event - will be filtered
            return

        # === HIJACK ANNOUNCEMENT ===
        elif action == "hijack_announcement":
            bmp_gen.generate(
                {
                    "prefix": prefix,
                    "as_path": entry["as_path"],
                    "origin_as": entry["origin_as"],
                    "next_hop": entry["next_hop"],
                    "peer_ip": entry["peer_ip"],
                    "peer_as": entry["peer_as"],
                    "rpki_state": entry["rpki_state"],
                    "scenario": scenario,
                }
            )

            # Use router syslog generator for BGP neighbor
            router_syslog_gen.bgp_neighbor_state_change(
                peer_ip=entry["peer_ip"],
                state="up",
                reason=f"announcing {prefix}",
                scenario=scenario,
            )

        # === RPKI VALIDATION CHECKS ===
        elif action == "rpki_validation_check":
            # Use RPKI generator for validator sync
            for validator in ["routinator", "cloudflare", "ripe"]:
                rpki_gen.validator_sync(
                    prefix=prefix,
                    origin_as=entry["origin_as"],
                    validator=validator,
                    rpki_state=entry["validation_result"].upper(),
                    revalidation=False,
                    scenario=scenario,
                )

        # === TRAFFIC ANOMALY ===
        elif action == "traffic_anomaly":
            # Traffic anomalies should come from monitoring system
            event_bus.publish(
                {
                    "event_type": "monitoring.anomaly",  # Need this event type
                    "timestamp": clock.now() + jitter(5),
                    "source": {"feed": "monitoring", "observer": "netsys-monitor"},
                    "attributes": {
                        "prefix": prefix,
                        "anomaly_type": "traffic_performance",
                        "rtt_ms": entry["rtt_ms"],
                        "baseline_ms": entry["baseline_ms"],
                        "packet_loss_pct": entry["packet_loss_pct"],
                        "region": entry["region"],
                        "severity": (
                            "high" if entry["packet_loss_pct"] > 1.0 else "medium"
                        ),
                    },
                    "scenario": scenario,
                }
            )

        # === MONITORING CHECKS ===
        elif action == "monitoring_check":
            # Internal monitoring status
            event_bus.publish(
                {
                    "event_type": "internal.monitoring_status",
                    "timestamp": clock.now() + jitter(5),
                    "attributes": {
                        "router": "monitoring-system",
                        "status": f"Attack operational: {entry.get('roa_status', 'unknown')}, {entry.get('bgp_announcement', 'unknown')}",
                    },
                    "scenario": scenario,
                }
            )

        # === WITHDRAWAL ANNOUNCEMENT ===
        elif action == "withdrawal_announcement":
            bmp_gen.generate(
                {
                    "prefix": prefix,
                    "as_path": [65001, entry["origin_as"]],
                    "origin_as": entry["origin_as"],
                    "next_hop": "198.51.100.254",
                    "peer_ip": "198.51.100.1",
                    "peer_as": 65001,
                    "is_withdraw": True,
                    "scenario": scenario,
                }
            )

        # === WITHDRAWAL PROPAGATION ===
        elif action == "withdrawal_propagation":
            for peer in entry.get("peers_removed", []):
                bmp_gen.generate(
                    {
                        "prefix": prefix,
                        "as_path": [peer, 64513],
                        "origin_as": 64513,
                        "next_hop": "198.51.100.254",
                        "peer_ip": f"10.0.0.{peer % 100}",
                        "peer_as": peer,
                        "is_withdraw": True,
                        "scenario": scenario,
                    }
                )

        # === TRAFFIC RECONVERGENCE ===
        elif action == "traffic_reconvergence":
            # Router syslog for reconvergence
            router_syslog_gen.configuration_change(
                user="bgp-process",
                change_type="route_reconvergence",
                target=f"{prefix} via AS{entry['via_as']} (reconvergence {entry['reconvergence_time_seconds']}s)",
                attack_step=attack_step,
            )

        # === VICTIM SERVICE RESTORED ===
        elif action == "victim_service_restored":
            # Use monitoring generator (if we had one) or publish structured event
            event_bus.publish(
                {
                    "event_type": "monitoring.anomaly",
                    "timestamp": clock.now() + jitter(5),
                    "source": {"feed": "monitoring", "observer": "netsys-monitor"},
                    "attributes": {
                        "prefix": prefix,
                        "anomaly_type": "service_restored",
                        "status": "normal",
                        # NO note field!
                    },
                    "scenario": scenario,
                }
            )

        # === TRAINING NOTES ===
        note = entry.get("note")
        if note:
            event_bus.publish(
                {
                    "event_type": "training.note",
                    "timestamp": clock.now(),
                    "line": f"SCENARIO: {note}",
                    "scenario": scenario,
                }
            )

    event_bus.subscribe(on_event)
