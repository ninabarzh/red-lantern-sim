# telemetry/generators/rpki_generator.py
"""
RPKI generator for Red Lantern simulator.
Emits RPKI events matching the existing RPKI adapter.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class RPKIGenerator:
    def __init__(
        self,
        clock: SimulationClock,
        event_bus: EventBus,
        scenario_name: str,
    ):
        """
        Initialize the generator.

        Args:
            clock: Shared simulation clock.
            event_bus: Shared event bus.
            scenario_name: Scenario name for correlation.
        """
        self.clock = clock
        self.event_bus = event_bus
        self.scenario_name = scenario_name

    def roa_creation(
        self,
        prefix: str,
        origin_as: int,
        max_length: int,
        registry: str,
        actor: str,
        status: str = "created",  # "created" or "accepted"
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit roa_creation event matching rpki.roa_creation adapter.
        """
        event = {
            "event_type": "rpki.roa_creation",  # Matches adapter
            "timestamp": self.clock.now(),
            "source": {"feed": "rpki", "observer": f"{registry.lower()}-registry"},
            "attributes": {
                "prefix": prefix,
                "origin_as": origin_as,
                "max_length": max_length,
                "registry": registry,
                "actor": actor,
                "status": status if status == "accepted" else None,
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)

    def roa_published(
        self,
        prefix: str,
        origin_as: int,
        trust_anchor: str,  # "RIPE", "ARIN", etc.
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit roa_published event matching rpki.roa_published adapter.
        """
        event = {
            "event_type": "rpki.roa_published",  # Matches adapter
            "timestamp": self.clock.now(),
            "source": {"feed": "rpki", "observer": f"{trust_anchor.lower()}-rpki"},
            "attributes": {
                "prefix": prefix,
                "origin_as": origin_as,
                "trust_anchor": trust_anchor.upper(),
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)

    def validator_sync(
        self,
        prefix: str,
        origin_as: int,
        validator: str,  # "routinator", "cloudflare", "ripe"
        rpki_state: str,  # "VALID", "INVALID", "NOT_FOUND"
        revalidation: bool = False,
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit validator_sync event matching rpki.validator_sync adapter.
        """
        # Map validator to observer
        observer_map = {
            "routinator": "rpki-validator-1",
            "cloudflare": "cloudflare-rpki",
            "ripe": "ripe-rpki",
        }

        event = {
            "event_type": "rpki.validator_sync",  # Matches adapter
            "timestamp": self.clock.now(),
            "source": {
                "feed": "rpki",
                "observer": observer_map.get(validator, validator),
            },
            "attributes": {
                "prefix": prefix,
                "origin_as": origin_as,
                "validator": validator,
                "rpki_state": rpki_state,
                "revalidation": revalidation,
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)

    def whois_query(
        self,
        prefix: str,
        allocated_to: str,
        registry: str,
        origin_as: int,
        scenario: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit whois_query event matching registry.whois adapter.
        """
        event = {
            "event_type": "registry.whois",  # Matches adapter
            "timestamp": self.clock.now(),
            "source": {"feed": "registry", "observer": f"{registry.lower()}-whois"},
            "attributes": {
                "prefix": prefix,
                "allocated_to": allocated_to,
                "registry": registry,
                "origin_as": origin_as,
            },
            "scenario": scenario
            or {
                "name": self.scenario_name,
                "attack_step": None,
                "incident_id": None,
            },
        }
        self.event_bus.publish(event)
