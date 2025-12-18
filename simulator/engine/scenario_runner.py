"""
Scenario runner for the Red Lantern BGP attack-chain simulator.

Responsibilities:

- Load a scenario definition from YAML
- Advance simulated time deterministically
- Hand events to the EventBus
- Remain agnostic about attack content
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
        Load the scenario YAML from disk and validate structure.
        """
        with self.scenario_path.open("r", encoding="utf-8") as fh:
            self.scenario = yaml.safe_load(fh)

        if not isinstance(self.scenario, dict):
            raise ValueError("Scenario file must be a YAML mapping (dict)")

        if "timeline" not in self.scenario:
            raise ValueError("Scenario is missing a 'timeline' section")

        if not isinstance(self.scenario["timeline"], list):
            raise ValueError("'timeline' must be a list of events")

    def run(self, close_bus: bool = False) -> None:
        """
        Run the scenario from start to finish.

        Args:
            close_bus: whether to close the EventBus after execution
                       (use False if running multiple scenarios in one session)
        """
        timeline: List[Dict[str, Any]] = sorted(
            self.scenario.get("timeline", []),
            key=lambda e: e.get("t", 0),
        )

        for entry in timeline:
            target_time = entry.get("t", 0)
            self.clock.advance_to(target_time)

            # Wrap event with scenario metadata
            event = {
                "timestamp": self.clock.now(),
                "scenario_id": self.scenario.get("id"),
                "entry": entry,
            }

            self.event_bus.publish(event)

        if close_bus:
            self.event_bus.close()

    def reset(self) -> None:
        """
        Reset the scenario runner and its clock.
        """
        self.clock.reset()
        # Do not automatically clear event bus; let caller decide
