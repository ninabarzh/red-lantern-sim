# simulator/cli.py

from __future__ import annotations
import argparse
import sys
from pathlib import Path
import json
from typing import Any, List
import signal

from simulator.engine.event_bus import EventBus
from simulator.engine.clock import SimulationClock
from simulator.engine.scenario_runner import ScenarioRunner
from simulator.engine.simulation_engine import run_with_background
from simulator.feeds.bgp.bgp_noise_feed import BGPNoiseFeed
from simulator.feeds.change_mgmt.cmdb_noise_feed import CMDBNoiseFeed
from simulator.output.adapter import ScenarioAdapter


def main(argv: list[str] | None = None) -> int | None:
    parser = argparse.ArgumentParser(
        prog="simulator.cli",
        description="Run a Red Lantern BGP scenario with modular log adapters",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "scenario",
        type=Path,
        help="Path to the scenario YAML file",
    )
    parser.add_argument(
        "--mode",
        choices=["practice", "training"],
        default="practice",
        help=(
            "Select mode: 'practice' for realistic logs, "
            "'training' adds extra training lines (SCENARIO: debug lines)"
        ),
    )
    parser.add_argument(
        "--output",
        choices=["cli", "json"],
        default="cli",
        help="Output mode: 'cli' prints lines to stdout; 'json' dumps transformed events to a JSON file",
    )
    parser.add_argument(
        "--json-file",
        type=Path,
        default=Path("scenario_output.json"),
        help="Path to JSON output file if --output=json",
    )
    parser.add_argument(
        "--background",
        action="store_true",
        help="Enable background noise feeds (BGP churn, CMDB changes)",
    )
    parser.add_argument(
        "--bgp-noise-rate",
        type=float,
        default=0.5,
        help="BGP updates per second (default: 0.5)",
    )
    parser.add_argument(
        "--cmdb-noise-rate",
        type=float,
        default=0.1,
        help="CMDB changes per second (default: 0.1)",
    )

    args = parser.parse_args(argv)

    if not args.scenario.exists():
        print(f"Scenario file not found: {args.scenario}", file=sys.stderr)
        return 1

    # Initialize components
    event_bus = EventBus()
    clock = SimulationClock()
    adapter = ScenarioAdapter()

    transformed_lines: List[str] = []
    transformed_events: List[dict[str, Any]] = []

    def handle_event(event: dict[str, Any]) -> None:
        # Transform event via adapter
        lines = adapter.transform(event)
        for line in lines:
            if not line:
                continue

            # Skip SCENARIO debug lines in practice mode
            if args.mode == "practice" and line.startswith("SCENARIO:"):
                continue

            event_record = {"line": line}
            if args.mode == "training":
                event_record["original_event"] = event

            transformed_lines.append(line)
            transformed_events.append(event_record)

            if args.output == "cli":
                print(line)

    event_bus.subscribe(handle_event)

    # Load scenario
    runner = ScenarioRunner(scenario_path=args.scenario, event_bus=event_bus)
    runner.clock = clock  # Share the clock

    try:
        runner.load()
    except Exception as exc:
        print(f"Failed to load scenario: {exc}", file=sys.stderr)
        return 2

    # Load optional telemetry if present
    telemetry_path = args.scenario.parent / "telemetry.py"
    if telemetry_path.exists():
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            f"{runner.scenario.get('id')}_telemetry", telemetry_path
        )
        if spec is None or spec.loader is None:
            print(f"Could not load telemetry module from {telemetry_path}", file=sys.stderr)
            return 2
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "register"):
            print(f"{telemetry_path} does not define register()", file=sys.stderr)
            return 2
        module.register(event_bus=event_bus, clock=clock, scenario_name=runner.scenario.get("id"))

    # Run simulation
    try:
        if args.background:
            # Create background feeds
            background_feeds = [
                BGPNoiseFeed(update_rate=args.bgp_noise_rate),
                CMDBNoiseFeed(change_rate=args.cmdb_noise_rate),
            ]

            if args.output == "cli":
                print(
                    f"[INFO] Background noise enabled: "
                    f"{args.bgp_noise_rate} BGP updates/sec, "
                    f"{args.cmdb_noise_rate} CMDB changes/sec",
                    file=sys.stderr
                )

            # Run with background noise
            run_with_background(runner, background_feeds, event_bus, clock)
        else:
            # Run scenario only (original behavior)
            runner.run()

    except Exception as exc:
        print(f"Simulation failed: {exc}", file=sys.stderr)
        return 3

    # Dump JSON output if requested
    if args.output == "json":
        try:
            args.json_file.parent.mkdir(parents=True, exist_ok=True)
            with args.json_file.open("w", encoding="utf-8") as f:
                json.dump(transformed_events, f, indent=2)
            print(f"Transformed scenario JSON dumped to {args.json_file}")
        except Exception as exc:
            print(f"Failed to write JSON file: {exc}", file=sys.stderr)
            return 4

    return 0  # success


if __name__ == "__main__":

    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # Ignore broken pipe
    sys.exit(main())
