"""
Simulation engine for the Red Lantern BGP attack-chain simulator.

The engine coordinates background feeds that emit events alongside scenarios.
Background feeds run independently, generating realistic noise that occurs
before, during, and after the scenario timeline.
"""

from typing import Any

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus


class BackgroundFeed:
    """
    A background feed generates time-stamped events independently of scenarios.

    These events represent normal operational activity:
    - BGP routing updates
    - Configuration changes
    - Maintenance windows
    """

    def generate_events(self, duration: int) -> list[tuple[int, dict[str, Any]]]:
        """
        Generate all background events for the simulation duration.

        Args:
            duration: Total simulation time in seconds

        Returns:
            List of (timestamp, event_dict) tuples
        """
        raise NotImplementedError("Subclasses must implement generate_events()")


def run_with_background(
    scenario_runner,
    background_feeds: list[BackgroundFeed],
    event_bus: EventBus,
    clock: SimulationClock,
) -> None:
    """
    Run a scenario with background noise.

    This function:
    1. Collects all events from scenario and background feeds
    2. Sorts them by timestamp
    3. Advances the clock and publishes events in order

    Args:
        scenario_runner: Loaded ScenarioRunner instance
        background_feeds: List of background feed instances
        event_bus: EventBus to publish all events to
        clock: Shared SimulationClock
    """
    # Determine simulation duration from scenario
    scenario_timeline = scenario_runner.scenario.get("timeline", [])
    duration = max(
        (entry.get("t", 0) for entry in scenario_timeline),
        default=3600
    )

    # Collect scenario events
    all_events: list[tuple[int, dict[str, Any]]] = []

    for entry in scenario_timeline:
        timestamp = entry.get("t", 0)
        event_data = {
            "source": "scenario",
            "scenario_id": scenario_runner.scenario.get("id"),
            "entry": entry,
        }
        all_events.append((timestamp, event_data))

    # Collect background events
    for feed in background_feeds:
        all_events.extend(feed.generate_events(duration))

    # Sort all events by timestamp
    all_events.sort(key=lambda x: x[0])

    # Execute timeline
    for timestamp, event_data in all_events:
        clock.advance_to(timestamp)

        # Add timestamp to event
        event = {
            "timestamp": clock.now(),
            **event_data
        }

        event_bus.publish(event)
