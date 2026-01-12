"""Telemetry mapping for Playbook 2: ROA Scope Expansion and Validation Mapping.

Phase 2 of a multi-stage control-plane operation:
- Create fraudulent ROA for victim prefix using compromised credentials
- Observe global RPKI validation behavior with proper propagation
- Establish monitoring showing attack persistence

REALISM: Shows full attack lifecycle (initial acceptance + ongoing validation)
"""

import random
from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.rpki_generator import RPKIGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 2 scenario."""

    # INITIALIZE GENERATORS
    bmp_generator = BMPTelemetryGenerator(
        scenario_id="playbook2_roa_expansion",
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
        prefix = entry.get("prefix", "unknown")

        # Create proper incident ID
        if action in ["phase1_complete", "phase2_complete"]:
            incident_id = f"{scenario_name}-{action}"
        elif prefix != "unknown":
            incident_id = f"{scenario_name}-{prefix}-{attack_step}"
        else:
            incident_id = f"{scenario_name}-{attack_step}"

        scenario_metadata = {
            "name": scenario_name,
            "attack_step": attack_step,
            "incident_id": incident_id,
        }

        # === 1. PHASE TRANSITIONS ===
        if action == "phase1_complete":
            # Phase transition event - use internal.documentation for BASELINE
            event_bus.publish(
                {
                    "event_type": "internal.documentation",
                    "timestamp": clock.now(),
                    "attributes": {
                        "action": action,
                        "attack_step": attack_step,
                        "our_prefix": entry.get("our_prefix", "unknown"),
                        "target_prefix": entry.get("target_prefix", "unknown"),
                        "target_roa_status": entry.get("target_roa_status", "unknown"),
                        "our_roa_status": "valid",  # From phase 1
                    },
                    "scenario": scenario_metadata,
                }
            )
            return

        elif action == "phase2_complete":
            # Only show in training mode
            return

        # === 2. CREDENTIAL COMPROMISE ===
        if action == "credential_use":
            user = entry.get("user", "unknown")
            source_ip = entry.get("source_ip", "unknown")
            system = entry.get("system", "unknown")

            # Use router.syslog for credential access - format similar to Playbook 1
            registry = system.replace("_portal", "").upper()
            router_syslog_gen.configuration_change(
                user=user,
                change_type="registry_access",  # Consistent with Playbook 1 style
                target=f"{registry} portal access from {source_ip}",
                attack_step=attack_step,
            )

        # === 3. FRAUDULENT ROA CREATION ===
        elif action == "roa_creation":
            origin_as = entry.get("origin_as")
            max_length = entry.get("max_length", 25)
            registry = entry.get("registry", "ARIN")
            actor = entry.get("actor", "unknown")

            # USE RPKI GENERATOR FOR ROA CREATION
            rpki_gen.roa_creation(
                prefix=prefix,
                origin_as=origin_as,
                max_length=max_length,
                registry=registry,
                actor=actor,
                status="created",
                scenario=scenario_metadata,
            )

            # In Playbook 2, acting as legitimate maintainer implies automatic acceptance
            # Add a ROA accepted event for consistency with Playbook 1
            event_bus.publish(
                {
                    "event_type": "rpki.roa_creation",
                    "timestamp": clock.now() + jitter(60),  # 1 minute later
                    "source": {
                        "feed": "rpki",
                        "observer": f"{registry.lower()}-registry",
                    },
                    "attributes": {
                        "prefix": prefix,
                        "origin_as": origin_as,
                        "registry": registry,
                        "status": "accepted",  # Mark as accepted
                    },
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": f"{scenario_name}-{prefix}-accepted",
                    },
                }
            )

        # === 4. ROA PUBLISHED ===
        elif action == "roa_published":
            origin_as = entry.get("origin_as")
            trust_anchor = entry.get("trust_anchor", "arin")

            # USE RPKI GENERATOR FOR ROA PUBLISHED
            rpki_gen.roa_published(
                prefix=prefix,
                origin_as=origin_as,
                trust_anchor=trust_anchor,
                scenario=scenario_metadata,
            )

        # === 5. VALIDATOR SYNC (INITIAL + RE-VALIDATION) ===
        elif action == "validator_sync":
            origin_as = entry.get("origin_as")
            validator = entry.get("validator", "unknown")
            rpki_state = entry.get("rpki_state", "valid").upper()

            # USE RPKI GENERATOR FOR VALIDATOR SYNC
            rpki_gen.validator_sync(
                prefix=prefix,
                origin_as=origin_as,
                validator=validator,
                rpki_state=rpki_state,
                revalidation=False,  # Initial sync
                scenario=scenario_metadata,
            )

            # === OPTIONAL RE-VALIDATION HOURS LATER (attack persistence) ===
            # Only for "roa_poisoning" phase, 50% chance per validator
            if attack_step == "roa_poisoning" and random.random() > 0.5:
                # Re-validation 4-24 hours later
                recheck_hours = random.randint(4, 24)
                recheck_seconds = recheck_hours * 3600 + jitter(1800)  # ±30 min
                recheck_time = clock.now() + recheck_seconds

                # Map validator to observer
                observer_map = {
                    "routinator": "rpki-validator-1",
                    "cloudflare": "cloudflare-rpki",
                    "ripe": "ripe-rpki",
                }

                # Publish delayed revalidation event
                event_bus.publish(
                    {
                        "event_type": "rpki.validator_sync",
                        "timestamp": recheck_time,
                        "source": {
                            "feed": "rpki",
                            "observer": observer_map.get(validator, validator),
                        },
                        "attributes": {
                            "prefix": prefix,
                            "origin_as": origin_as,
                            "validator": validator,
                            "rpki_state": rpki_state,
                            "revalidation": True,
                        },
                        "scenario": {
                            "name": scenario_name,
                            "attack_step": "monitoring",
                            "incident_id": f"{scenario_name}-monitoring-{prefix}",
                        },
                    }
                )

        # === 6. ROA SET STATE (MULTIPLE ROAS) ===
        elif action == "roa_set_state":
            # If multiple ROAs exist for this prefix; per-origin validation applies
            # origins_present = entry.get("origins_present", [])

            # Use RPKI generator for validator sync showing current state
            rpki_gen.validator_sync(
                prefix=prefix,
                origin_as=64513,  # Our attacking AS
                validator="routinator",
                rpki_state="VALID",
                revalidation=False,
                scenario=scenario_metadata,
            )

        # === 7. OBSERVATION START ===
        elif action == "observation_start":
            focus = entry.get("focus", "unknown")

            # This is internal - use internal event that will be filtered
            event_bus.publish(
                {
                    "event_type": "internal.monitoring_status",
                    "timestamp": clock.now() + jitter(5),
                    "attributes": {
                        "router": "monitoring-system",
                        "status": f"Starting {focus} observation",
                    },
                    "scenario": scenario_metadata,
                }
            )

        # === 8. TEST ANNOUNCEMENTS (VALIDATION MAPPING) ===
        elif action == "test_announcement":
            origin_as = entry.get("origin_as")
            region = entry.get("region", "unknown")
            # observed_result = entry.get("observed_result", "unknown")

            # Determine peer based on region
            if region == "AMER":
                peer_ip, peer_as = "10.0.0.10", 65500
            elif region == "EMEA":
                peer_ip, peer_as = "10.0.0.20", 65501
            else:  # APAC
                peer_ip, peer_as = "10.0.0.30", 65502

            # USE BMP GENERATOR FOR ROUTE ANNOUNCEMENT
            bmp_generator.generate(
                {
                    "prefix": prefix,
                    "as_path": [peer_as, origin_as],
                    "origin_as": origin_as,
                    "next_hop": "192.0.2.254",
                    "peer_ip": peer_ip,
                    "peer_as": peer_as,
                    "rpki_state": "INVALID",  # Different origin = INVALID
                    "scenario": scenario_metadata,
                }
            )

            # NO redundant [OBSERVATION] training.note - BMP logs already show the announcement

        # === 9. TEST WITHDRAWAL ===
        elif action == "test_withdrawal":
            origin_as = entry.get("origin_as")

            # Determine peer (use EMEA as default for withdrawal)
            peer_ip, peer_as = "10.0.0.20", 65501

            # USE BMP GENERATOR FOR WITHDRAWAL
            bmp_generator.generate(
                {
                    "prefix": prefix,
                    "as_path": [peer_as, origin_as],
                    "origin_as": origin_as,
                    "next_hop": "192.0.2.254",
                    "peer_ip": peer_ip,
                    "peer_as": peer_as,
                    "is_withdraw": True,
                    "scenario": scenario_metadata,
                }
            )

        # === 10. VALIDATION MAP COMPLETE ===
        elif action == "validation_map_complete":
            # Emit a single summary event if you ever want a campaign report. Not now.
            # qualitative_results = entry.get("qualitative_results", {})
            target_region = entry.get("target_region", "unknown")

            # This is analysis - use internal event that will be filtered
            event_bus.publish(
                {
                    "event_type": "internal.documentation",
                    "timestamp": clock.now() + jitter(5),
                    "attributes": {
                        "action": "validation_analysis",
                        "target_region": target_region,
                    },
                    "scenario": scenario_metadata,
                }
            )

        # === 11. MONITORING EVENTS ===
        elif action == "monitoring_deployed":
            check_interval = entry.get("check_interval", 300)
            target_prefix = entry.get("target_prefix", prefix)

            # USE ROUTER SYSLOG FOR MONITORING DEPLOYMENT
            router_syslog_gen.configuration_change(
                user="operator@attacker-as64513.net",
                change_type="monitoring_deployed",
                target=f"RPKI monitoring for {target_prefix} (interval: {check_interval}s)",
                attack_step=attack_step,
            )

        elif action == "monitoring_baseline":
            # The emitted signal is our_roa_present, which is the only thing that affects behaviour.
            # roa_count = entry.get("roa_count", 0)
            our_roa_present = entry.get("our_roa_present", False)

            # Use RPKI generator for monitoring check
            rpki_gen.validator_sync(
                prefix=prefix,
                origin_as=64513,
                validator="monitoring-system",
                rpki_state="VALID" if our_roa_present else "NOT_FOUND",
                revalidation=False,
                scenario=scenario_metadata,
            )

        elif action == "stability_check":
            # Telemetry should show checks, not reasoning.
            # window = entry.get("observation_window_hours", 48)
            # changes = entry.get("changes_detected", False)

            # Use RPKI generator for stability check
            rpki_gen.validator_sync(
                prefix=prefix,
                origin_as=64513,
                validator="monitoring-system",
                rpki_state="VALID",
                revalidation=True,  # Mark as revalidation check
                scenario=scenario_metadata,
            )

        # === TRAINING NOTES ===
        note = entry.get("note")
        if note:
            event_bus.publish(
                {
                    "event_type": "training.note",
                    "timestamp": clock.now(),
                    "line": f"SCENARIO: {note}",
                    "scenario": scenario_metadata,
                }
            )

    event_bus.subscribe(on_timeline_event)
