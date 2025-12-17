"""
Scenario runner for the Red Lantern BGP attack-chain simulator.

This module is deliberately dull. It does not know what an attack is,
does not attempt to detect anything, and does not care whether events
are malicious or benign. Its sole responsibility is to:

- Load a scenario definition
- Advance simulated time
- Emit events in the correct order
- Hand those events to the event bus

If you are tempted to add detection logic here, stop. That belongs on
the blue side of the lanterns.
"""

from pathlib import Path
from typing import Any, Dict, List
import yaml

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class ScenarioRunner:
    """
    Executes a single attack scenario in simulated time.
    """

    def __init__(self, scenario_path: Path, event_bus: EventBus) -> None:
        self.scenario_path = scenario_path
        self.event_bus = event_bus
        self.clock = SimulationClock()
        self.scenario: Dict[str, Any] = {}

    def load(self) -> None:
        """
        Load the scenario YAML from disk.
        """
        with self.scenario_path.open("r", encoding="utf-8") as fh:
            self.scenario = yaml.safe_load(fh)

        if "timeline" not in self.scenario:
            raise ValueError("Scenario is missing a timeline section")

    def run(self) -> None:
        """
        Run the scenario from start to finish.
        """
        timeline: List[Dict[str, Any]] = sorted(
            self.scenario.get("timeline", []),
            key=lambda e: e.get("t", 0),
        )

        for entry in timeline:
            target_time = entry.get("t", 0)
            self.clock.advance_to(target_time)

            event = {
                "time": self.clock.now(),
                "event": entry,
                "scenario_id": self.scenario.get("id"),
            }

            self.event_bus.publish(event)

        self.event_bus.close()
