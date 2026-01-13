"""Telemetry mapping for Playbook 1: RPKI Reconnaissance and ROA Creation."""

import random
from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus

# ADD RPKI GENERATOR IMPORT
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.rpki_generator import RPKIGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 1."""

    # INITIALIZE THREE GENERATORS
    bmp_generator = BMPTelemetryGenerator(
        scenario_id="playbook1_rpki_recon",
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

    def on_timeline_event(event: dict[str, Any]) -> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        attack_step = entry.get("attack_step", "unknown")
        prefix = (
            entry.get("prefix")
            or entry.get("target_prefix")
            or entry.get("our_prefix")
            or "unknown"
        )
        incident_id = f"{scenario_name}-{attack_step}-{prefix}"

        scenario_metadata = {
            "name": scenario_name,
            "attack_step": attack_step,
            "incident_id": incident_id,
        }

        # === 1. BASELINE ANNOUNCEMENTS ===
        if action == "baseline_announcement":
            origin_as = entry.get("origin_as")
            as_path = entry.get("as_path", [])
            next_hop = entry.get("next_hop", "192.0.2.254")

            # Determine RPKI state
            rpki_state = None
            if prefix == "203.0.113.0/24":
                rpki_state = "NOT_FOUND"
            elif entry.get("rpki_state"):
                rpki_state = entry.get("rpki_state").upper()

            # USE BMP GENERATOR
            bmp_generator.generate(
                {
                    "prefix": prefix,
                    "as_path": as_path,
                    "origin_as": origin_as,
                    "next_hop": next_hop,
                    "peer_ip": "10.0.0.2",
                    "peer_as": as_path[0] if as_path else origin_as,
                    "rpki_state": rpki_state,
                    "scenario": scenario_metadata,
                }
            )

            # USE STRUCTURED ROUTER SYSLOG GENERATOR (FIXED)
            if attack_step == "baseline":
                router_syslog_gen.bgp_neighbor_state_change(
                    peer_ip="10.0.0.2",
                    state="up",
                    reason="",
                    scenario=scenario_metadata,
                )

        # === 2. VISIBLE RECONNAISSANCE ===
        elif action == "recon_complete":
            target_prefix = entry.get("target_prefix", prefix)
            target_as = entry.get("target_as")
            roa_status = entry.get("roa_status", "not_found").upper()

            # USE RPKI GENERATOR FOR WHOIS
            rpki_gen.whois_query(
                prefix=target_prefix,
                allocated_to="Victim Corp",
                registry="RIPE",
                origin_as=target_as,
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": f"{scenario_name}-{attack_step}-{target_prefix}",
                },
            )

            # KEEP DIRECT EVENT FOR RPKI QUERY (no generator method for this yet)
            event_bus.publish(
                {
                    "event_type": "rpki.query",
                    "timestamp": clock.now() + jitter(10),
                    "source": {"feed": "rpki", "observer": "rpki-validator-1"},
                    "attributes": {
                        "prefix": target_prefix,
                        "origin_as": target_as,
                        "query_type": "status_check",
                        "validation_result": roa_status,
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": f"{scenario_name}-{attack_step}-{target_prefix}",
                    },
                }
            )

        # === 3. ROA CREATION REQUEST ===
        elif action == "roa_creation_request":
            origin_as = entry.get("origin_as")
            max_length = entry.get("max_length", 24)
            registry = entry.get("registry", "RIPE")
            actor = entry.get("actor", "unknown")

            # USE ROUTER SYSLOG GENERATOR FOR CONFIGURATION CHANGE (STRUCTURED)
            router_syslog_gen.configuration_change(
                user=actor,
                change_type="roa_request",
                target=f"{prefix} AS{origin_as}",
                attack_step=attack_step,
            )

            # USE RPKI GENERATOR FOR ROA CREATION
            rpki_gen.roa_creation(
                prefix=prefix,
                origin_as=origin_as,
                max_length=max_length,
                registry=registry,
                actor=actor,
                status="created",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === 4. ROA ACCEPTED ===
        elif action == "roa_accepted":
            origin_as = entry.get("origin_as")

            # USE RPKI GENERATOR FOR ROA ACCEPTED
            rpki_gen.roa_creation(
                prefix=prefix,
                origin_as=origin_as,
                max_length=24,  # Default if not specified
                registry="RIPE",
                actor="registry-automation",
                status="accepted",
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === 5. ROA PUBLISHED ===
        elif action == "roa_published":
            origin_as = entry.get("origin_as")
            trust_anchor = entry.get("trust_anchor", "RIPE").upper()

            # USE RPKI GENERATOR FOR ROA PUBLISHED
            rpki_gen.roa_published(
                prefix=prefix,
                origin_as=origin_as,
                trust_anchor=trust_anchor,
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === 6. VALIDATOR SYNC ===
        elif action == "validator_check":
            origin_as = entry.get("origin_as")
            validator = entry.get("validator", "unknown")
            rpki_state = entry.get("rpki_state", "valid").upper()

            # USE RPKI GENERATOR FOR VALIDATOR SYNC
            rpki_gen.validator_sync(
                prefix=prefix,
                origin_as=origin_as,
                validator=validator,
                rpki_state=rpki_state,
                revalidation=False,
                scenario={
                    "name": scenario_name,
                    "attack_step": attack_step,
                    "incident_id": incident_id,
                },
            )

        # === 7. INTERNAL EVENTS ===
        elif action == "baseline_documented":
            # KEEP DIRECT FOR INTERNAL EVENTS
            event_bus.publish(
                {
                    "event_type": "internal.documentation",
                    "timestamp": clock.now() + jitter(5),
                    "attributes": {
                        "action": action,
                        "target_prefix": entry.get("target_prefix"),
                        "target_roa_status": entry.get("target_roa_status"),
                        "our_prefix": entry.get("our_prefix"),
                        "our_roa_status": entry.get("our_roa_status"),
                        "attack_step": attack_step,
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        elif action in {"waiting_period_complete", "phase1_complete"}:
            # KEEP DIRECT FOR INTERNAL EVENTS
            event_bus.publish(
                {
                    "event_type": "internal.phase_event",
                    "timestamp": clock.now() + jitter(5),
                    "attributes": {
                        "action": action,
                        "attack_step": attack_step,
                        "days_elapsed": entry.get("days_elapsed", 0),
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

        # === TRAINING NOTES ===
        note = entry.get("note")
        if note:
            # KEEP DIRECT FOR TRAINING NOTES
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

    event_bus.subscribe(on_timeline_event)
