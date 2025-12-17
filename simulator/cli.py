"""
Command-line interface for the Red Lantern BGP attack-chain simulator.

This CLI is intentionally thin. It wires together the scenario runner
and the event bus, performs basic argument validation, and starts the
simulation. It does not contain scenario logic, detection logic, or
telemetry formatting.

If this file grows large, something has gone wrong.
"""

import argparse
from pathlib import Path
import sys

from simulator.engine.scenario_runner import ScenarioRunner
from simulator.engine.event_bus import EventBus


def print_event(event):
    """
    Default event handler.

    For now, events are written to stdout as plain dictionaries. More
    sophisticated emitters (JSON, sockets, Wazuh queues) are expected to
    subscribe to the event bus in the future.
    """
    print(event)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a Red Lantern BGP attack-chain scenario",
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

    runner = ScenarioRunner(scenario_path=scenario_path, event_bus=event_bus)

    try:
        runner.load()
        runner.run()
    except Exception as exc:  # Fail loudly and early
        print(f"Simulation failed: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
