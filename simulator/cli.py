# simulator/cli.py

from __future__ import annotations
import argparse
import sys
from pathlib import Path
import json
from typing import Any, List

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner
from simulator.output.adapter import ScenarioAdapter


def main(argv: list[str] | None = None) -> int | None:
    parser = argparse.ArgumentParser(
        description="Run a Red Lantern BGP scenario with modular log adapters"
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

    args = parser.parse_args(argv)

    if not args.scenario.exists():
        print(f"Scenario file not found: {args.scenario}", file=sys.stderr)
        return 1

    event_bus = EventBus()
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
                event_record["original_event"] = event  # include scenario metadata only in training mode

            # Only append lines that pass the mode filter
            transformed_lines.append(line)
            transformed_events.append(event_record)  # optional: keep original_event if desired

            if args.output == "cli":
                print(line)

    event_bus.subscribe(handle_event)

    # Load and run scenario
    runner = ScenarioRunner(scenario_path=args.scenario, event_bus=event_bus)

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
        module.register(event_bus=event_bus, clock=runner.clock, scenario_name=runner.scenario.get("id"))

    try:
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


if __name__ == "__main__":
    sys.exit(main())
