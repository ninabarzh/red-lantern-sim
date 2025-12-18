"""
Command-line interface for the Red Lantern BGP attack-chain simulator.
"""

import argparse
import sys
from pathlib import Path
from typing import Any

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner

from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


def print_event(event: dict[str, Any]) -> None:
    """Default event handler: dump everything to stdout."""
    print(event)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a Red Lantern BGP attack-chain scenario"
    )
    parser.add_argument(
        "scenario",
        type=Path,
        help="Path to the scenario YAML file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scenario_path: Path = args.scenario

    if not scenario_path.exists():
        print(f"Scenario file not found: {scenario_path}", file=sys.stderr)
        return 1

    event_bus = EventBus()
    event_bus.subscribe(print_event)

    runner = ScenarioRunner(
        scenario_path=scenario_path,
        event_bus=event_bus,
    )

    try:
        runner.load()
    except Exception as exc:
        print(f"Failed to load scenario: {exc}", file=sys.stderr)
        return 2

    # ---- Scenario identity (single source of truth) ----
    scenario_id = runner.scenario.get("id")

    # ---- Telemetry generators (shared clock & bus) ----
    bgp_gen = BGPUpdateGenerator(
        clock=runner.clock,
        event_bus=event_bus,
        scenario_name=scenario_id,
    )

    syslog_gen = RouterSyslogGenerator(
        clock=runner.clock,
        event_bus=event_bus,
        router_name="R1",
        scenario_name=scenario_id,
    )

    latency_gen = LatencyMetricsGenerator(
        clock=runner.clock,
        event_bus=event_bus,
        scenario_name=scenario_id,
    )

    # ---- Scenario → telemetry translation layer ----
    def telemetry_listener(event: dict[str, Any]) -> None:
        entry = event.get("entry", {})
        action = entry.get("action")

        if action == "announce":
            bgp_gen.emit_update(
                prefix=entry["prefix"],
                as_path=[65001, 65002],
                origin_as=65002,
                next_hop="192.0.2.1",
                attack_step="announce",
            )
            syslog_gen.bgp_session_reset(
                peer_ip="192.0.2.1",
                reason="session flapped",
                attack_step="announce",
            )

        elif action == "withdraw":
            bgp_gen.emit_withdraw(
                prefix=entry["prefix"],
                withdrawn_by_as=65002,
                attack_step="withdraw",
            )
            syslog_gen.prefix_limit_exceeded(
                peer_ip="192.0.2.1",
                limit=100,
                attack_step="withdraw",
            )

        elif action == "latency_spike":
            latency_gen.emit(
                source_router="R1",
                target_router="R2",
                latency_ms=150.0,
                jitter_ms=15.0,
                packet_loss_pct=0.1,
                attack_step="latency_spike",
            )

    event_bus.subscribe(telemetry_listener)

    try:
        runner.run()
    except Exception as exc:
        print(f"Simulation failed: {exc}", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
