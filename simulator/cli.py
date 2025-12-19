"""
Command-line interface for the Red Lantern BGP attack-chain simulator.
"""

import argparse
import sys
import importlib.util
from pathlib import Path
from typing import Any
import socket
import json

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner


def print_event(event: dict[str, Any]) -> None:
    """Default event handler: dump everything to stdout."""
    print(event)

# def send_to_wazuh(event):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.sendto(json.dumps(event).encode(), ("localhost", 1514))
#     sock.close()


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


def load_scenario_telemetry(
    scenario_path: Path,
    event_bus: EventBus,
    clock,
    scenario_id: str,
) -> None:
    """
    Load and register scenario-specific telemetry if telemetry.py exists
    alongside the scenario.yaml.
    """
    telemetry_path = scenario_path.parent / "telemetry.py"
    if not telemetry_path.exists():
        return

    spec = importlib.util.spec_from_file_location(
        f"{scenario_id}_telemetry",
        telemetry_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load telemetry module from {telemetry_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "register"):
        raise RuntimeError(
            f"{telemetry_path} does not define a register(event_bus, clock, scenario_name)"
        )

    module.register(
        event_bus=event_bus,
        clock=clock,
        scenario_name=scenario_id,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scenario_path: Path = args.scenario

    if not scenario_path.exists():
        print(f"Scenario file not found: {scenario_path}", file=sys.stderr)
        return 1

    event_bus = EventBus()
    event_bus.subscribe(send_to_wazuh)

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
    if not scenario_id:
        print("Scenario has no id field", file=sys.stderr)
        return 2

    # ---- Load scenario-specific telemetry (THIS IS THE FIX) ----
    try:
        load_scenario_telemetry(
            scenario_path=scenario_path,
            event_bus=event_bus,
            clock=runner.clock,
            scenario_id=scenario_id,
        )
    except Exception as exc:
        print(f"Failed to load scenario telemetry: {exc}", file=sys.stderr)
        return 2

    try:
        runner.run()
    except Exception as exc:
        print(f"Simulation failed: {exc}", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
