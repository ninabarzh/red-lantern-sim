# scenarios/medium/playbook2/telemetry.py
"""
Telemetry mapping for Playbook 2: ROA Scope Expansion and Validation Mapping.

Emits simulator events reflecting:
- Compromised credential use
- ROA creation and publication with realistic timing
- Validator synchronisation with observer jitter
- Monitoring and stability assessment
"""

import random
from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator


def register(event_bus: EventBus, clock: SimulationClock, scenario_name: str) -> None:
    """Register telemetry generators for Playbook 2 scenario."""

    bmp_gen = BMPTelemetryGenerator(
        scenario_id=scenario_name,
        scenario_name="Playbook 2: ROA Scope Expansion and Validation Mapping",
        clock=clock,
        event_bus=event_bus,
    )

    syslog_gen = RouterSyslogGenerator(
        clock=clock,
        event_bus=event_bus,
        router_name="edge-router-01",
        scenario_name=scenario_name,
    )

    # small helper to add random jitter in seconds
    def jitter(seconds: float = 2.0) -> float:
        return random.uniform(0, seconds)

    def emit_rpki(
        event_type: str,
        attrs: dict[str, Any],
        observer: str | None = None,
        severity: str | None = None,
    ) -> None:
        """Emit RPKI-related syslog line with realistic jitter and optional severity override."""
        event_ts = clock.now() + jitter(3.0)
        rpki_event = {
            "event_type": event_type,
            "timestamp": event_ts,
            "source": {
                "feed": "rpki",
                "observer": observer or attrs.get("observer", "unknown"),
            },
            "attributes": attrs,
        }

        # Map severity based on event type, with small variation
        sev_map = {
            "rpki.roa_created": "notice",
            "rpki.roa_published": "info",
            "rpki.validator_sync": "info",
        }
        line_sev = severity or sev_map.get(event_type, "info")

        msg_parts = []
        if event_type == "rpki.roa_created":
            msg_parts.append(
                f"ROA created for {attrs['prefix']} "
                f"(origin AS{attrs['origin_as']}, maxLength /{attrs.get('max_length', 24)})"
            )
        elif event_type == "rpki.roa_published":
            msg_parts.append(
                f"ROA published: {attrs['prefix']} origin AS{attrs['origin_as']} in {attrs.get('trust_anchor', 'unknown')} repository"
            )
        elif event_type == "rpki.validator_sync":
            msg_parts.append(
                f"Validator sync: {observer or 'unknown-validator'} sees {attrs['prefix']} origin AS{attrs['origin_as']} -> {attrs.get('rpki_state', 'unknown')}"
            )

        syslog_gen.emit(
            message=" ".join(msg_parts),
            severity=line_sev,
            subsystem="rpki",
            scenario=rpki_event,
        )

        # Publish to event bus for other adapters if needed
        event_bus.publish(rpki_event)

    def on_timeline_event(event: dict[str, Any]) -> None:
        entry = event.get("entry")
        if not entry:
            return

        action = entry.get("action")
        prefix = entry.get("prefix", "unknown")
        attack_step = entry.get("attack_step", "unknown")
        incident_id = f"{scenario_name}-{prefix}-{attack_step}"

        # === ROA creation ===
        if action == "roa_creation":
            attrs = {
                "prefix": prefix,
                "origin_as": entry.get("origin_as"),
                "max_length": entry.get("max_length"),
                "actor": entry.get("actor"),
            }
            emit_rpki("rpki.roa_created", attrs, observer="edge-router-01")

        # === ROA publication ===
        elif action == "roa_published":
            attrs = {
                "prefix": prefix,
                "origin_as": entry.get("origin_as"),
                "trust_anchor": entry.get("trust_anchor"),
            }
            emit_rpki("rpki.roa_published", attrs, observer=entry.get("trust_anchor"))

        # === Validator sync for main validators ===
        elif action == "validator_sync":
            validators = ["routinator", "cloudflare", "ripe"]
            for val in validators:
                attrs = {
                    "prefix": prefix,
                    "origin_as": entry.get("origin_as"),
                    "rpki_state": entry.get("rpki_state", "valid"),
                }
                emit_rpki("rpki.validator_sync", attrs, observer=val)

        # === Test announcement for BMP / BGP realistic lines ===
        elif action == "test_announcement":
            bmp_gen.generate(
                {
                    "prefix": prefix,
                    "origin_as": entry.get("origin_as"),
                    "as_path": [65001, entry.get("origin_as")],
                    "peer_ip": "198.51.100.1",
                    "peer_as": 65001,
                    "peer_bgp_id": "198.51.100.1",
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )

            # Emit BGP syslog lines with small timestamp jitter
            for peer_as in [65001, 65002]:
                syslog_gen.emit(
                    message=f"BGP update received from AS{peer_as} for {prefix}",
                    severity="info",
                    subsystem="bgp",
                    scenario={
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                )
                syslog_gen.emit(
                    message=f"BGP update advertised to peer AS{peer_as}: {prefix} next-hop 192.0.2.254",
                    severity="info",
                    subsystem="bgp",
                    scenario={
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                )

        elif action == "test_withdrawal":
            bmp_gen.generate(
                {
                    "prefix": prefix,
                    "origin_as": entry.get("origin_as"),
                    "is_withdraw": True,
                    "scenario": {
                        "name": scenario_name,
                        "attack_step": attack_step,
                        "incident_id": incident_id,
                    },
                }
            )
            for peer_as in [65001, 65002]:
                syslog_gen.emit(
                    message=f"BGP withdraw: {prefix} to peer AS{peer_as}",
                    severity="info",
                    subsystem="bgp",
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

    event_bus.subscribe(on_timeline_event)
