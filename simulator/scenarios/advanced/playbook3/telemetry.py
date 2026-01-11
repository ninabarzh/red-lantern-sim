import random
from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 3: Prefix Hijacking with RPKI Validation Cover",
        clock=clock,
        event_bus=event_bus,
    )

    syslog = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
    )

    def on_event(event: dict[str, Any]) -> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix", "unknown")
        attack_step = entry.get("attack_step", "unknown")
        incident_id = f"{scenario_name}-{prefix}-{attack_step}"

        # === Announcement ===
        if action == "hijack_announcement":
            bmp_gen.generate(
                {
                    "prefix": prefix,
                    "as_path": entry["as_path"],
                    "origin_as": entry["origin_as"],
                    "next_hop": entry["next_hop"],
                    "peer_ip": entry["peer_ip"],
                    "peer_as": entry["peer_as"],
                    "rpki_state": entry["rpki_state"],
                }
            )

            syslog.emit(
                message=f"BGP announcement: {prefix} from AS{entry['origin_as']}, RPKI validation: valid",
                severity="info",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === RPKI checks (boringly correct) ===
        elif action == "rpki_validation_check":
            for v in ["routinator", "cloudflare", "ripe"]:
                syslog.emit(
                    message=f"RPKI validation: {prefix} AS{entry['origin_as']} -> valid ({v})",
                    severity=random.choice(["info", "notice"]),
                    subsystem="rpki",
                    scenario={
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                )

        # === Best path chaos ===
        elif action == "best_path_change":
            syslog.emit(
                message=(
                    f"BGP best path changed for {prefix}: "
                    f"{entry['old_path']} -> {entry['new_path']} "
                    f"(reason: {entry['reason']})"
                ),
                severity="warning",
                subsystem="bgp",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === Traffic pain ===
        elif action == "traffic_anomaly":
            syslog.emit(
                message=(
                    f"Traffic anomaly for {prefix}: "
                    f"RTT {entry['rtt_ms']}ms (baseline {entry['baseline_ms']}ms), "
                    f"packet loss {entry['packet_loss_pct']}%, "
                    f"region {entry['region']}"
                ),
                severity="err",
                subsystem="routing",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === Withdrawals ===
        elif action == "withdrawal_propagation":
            for peer in entry.get("peers_removed", []):
                syslog.emit(
                    message=f"BGP withdrawal: {prefix} from AS64513 to peer {peer}",
                    severity="notice",
                    subsystem="bgp",
                    scenario={
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                )

        # === Recovery ===
        elif action == "traffic_reconvergence":
            syslog.emit(
                message=(
                    f"Traffic restored for {prefix} via AS{entry['via_as']} "
                    f"(reconvergence {entry['reconvergence_time_seconds']}s)"
                ),
                severity="info",
                subsystem="routing",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        elif action == "victim_service_restored":
            syslog.emit(
                message=f"Victim traffic normal: {prefix}",
                severity="info",
                subsystem="routing",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === Training notes (SCENARIO lines) ===
        note = entry.get("note")
        if note:
            event_bus.publish(
                {
                    "event_type": "training.note",
                    "timestamp": clock.now(),
                    "line": f"SCENARIO: {note}",
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

    event_bus.subscribe(on_event)
