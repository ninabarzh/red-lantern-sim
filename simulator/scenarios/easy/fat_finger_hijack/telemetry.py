"""
Fat-finger hijack telemetry wiring.

This file does exactly one job:
take a scenario timeline and emit realistic telemetry
via the existing generators and the event bus.

It does NOT:
- detect attacks
- decide intent
- suppress events
- fix mistakes

If it feels underwhelming, good. That means detection
has to earn its keep.
"""

from datetime import timedelta

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus

from telemetry.generators.bgp_updates import (
    announce_prefix,
    withdraw_prefix,
)
from telemetry.generators.router_syslog import (
    bgp_neighbor_up,
    bgp_route_installed,
    bgp_route_withdrawn,
    bgp_duplicate_origin_warning,
)


class FatFingerHijackTelemetry:
    """
    Implements the telemetry stream for the classic
    'oops, wrong AS' scenario.

    Assumption:
    The operator meant well.
    The packets do not care.
    """

    def __init__(self, clock: SimulationClock, bus: EventBus, config: dict):
        self.clock = clock
        self.bus = bus
        self.cfg = config

        self.prefix = config["prefix"]
        self.legit_as = config["legitimate_as"]
        self.wrong_as = config["mistyped_as"]
        self.upstream_as = config["upstream_as"]
        self.peer_ip = config.get("peer_ip", "192.0.2.1")

    def run(self):
        """
        Execute the scenario timeline.
        Time moves forward. Mistakes happen.
        """

        # ---- Phase 0: calm, normal, nobody is watching ----
        self.bus.emit(
            announce_prefix(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.legit_as,
                as_path=[self.upstream_as, self.legit_as],
            )
        )

        self.bus.emit(
            bgp_neighbor_up(
                clock=self.clock,
                neighbor_ip=self.peer_ip,
                remote_as=self.upstream_as,
            )
        )

        self.bus.emit(
            bgp_route_installed(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.legit_as,
            )
        )

        self.clock.tick(timedelta(minutes=10))

        # ---- Phase 1: configuration change (the finger slips) ----
        self.bus.emit(
            announce_prefix(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.wrong_as,
                as_path=[self.upstream_as, self.wrong_as],
            )
        )

        self.bus.emit(
            bgp_duplicate_origin_warning(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.wrong_as,
            )
        )

        self.bus.emit(
            bgp_route_installed(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.wrong_as,
            )
        )

        # Let it propagate long enough to hurt,
        # short enough to claim innocence.
        self.clock.tick(timedelta(minutes=27))

        # ---- Phase 2: realisation dawns ----
        self.bus.emit(
            withdraw_prefix(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.wrong_as,
            )
        )

        self.bus.emit(
            bgp_route_withdrawn(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.wrong_as,
            )
        )

        # Restore correct announcement
        self.bus.emit(
            announce_prefix(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.legit_as,
                as_path=[self.upstream_as, self.legit_as],
            )
        )

        self.bus.emit(
            bgp_route_installed(
                clock=self.clock,
                prefix=self.prefix,
                origin_as=self.legit_as,
            )
        )

        # ---- Phase 3: silence, paperwork, denial ----
        self.clock.tick(timedelta(minutes=5))


def run(clock: SimulationClock, bus: EventBus, config: dict):
    """
    Entry point used by the scenario runner.

    Keeping this thin is intentional.
    """
    scenario = FatFingerHijackTelemetry(clock, bus, config)
    scenario.run()
