"""
Command-line interface for the Red Lantern BGP attack-chain simulator.
"""

import argparse
import sys
from pathlib import Path

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner


def print_event(event: dict) -> None:
    """Default event handler."""
    print(event)


def debug_listener(event: dict) -> None:
    """Minimal subscriber to prove event fan-out works."""
    print("DEBUG event received:", event)

    entry = event.get("entry", {})
    if entry.get("action") == "announce":
        print("DEBUG: would emit BGP UPDATE here")


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


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scenario_path: Path = args.scenario

    if not scenario_path.exists():
        print(f"Scenario file not found: {scenario_path}", file=sys.stderr)
        return 1

    event_bus = EventBus()
    event_bus.subscribe(print_event)
    event_bus.subscribe(debug_listener)  # ← THIS WAS MISSING

    runner = ScenarioRunner(
        scenario_path=scenario_path,
        event_bus=event_bus,
    )

    try:
        runner.load()
        runner.run()
    except Exception as exc:
        print(f"Simulation failed: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
