"""
Background configuration management noise feed.

Generates realistic, ongoing infrastructure changes to simulate normal
operational activity.
"""

import random
from typing import Any

from simulator.engine.simulation_engine import BackgroundFeed


class CMDBNoiseFeed(BackgroundFeed):
    """
    Produces background configuration change events.

    Simulates normal operational activity:
    - Maintenance windows
    - Software updates
    - Configuration changes
    - System restarts
    """

    def __init__(self, change_rate: float = 0.1, seed: int = 43):
        """
        Args:
            change_rate: Average changes per second
            seed: Random seed for determinism
        """
        self.change_rate = change_rate
        self.seed = seed

    def generate_events(self, duration: int) -> list[tuple[int, dict[str, Any]]]:
        """
        Generate deterministic background change management events.

        Args:
            duration: Simulation duration in seconds

        Returns:
            List of (timestamp, event_dict) tuples
        """
        rng = random.Random(self.seed)

        # Calculate total events
        total_events = int(duration * self.change_rate)

        events = []

        for _ in range(total_events):
            # Random timestamp within duration
            timestamp = rng.randint(0, duration)

            change_type = rng.choice([
                "software_update",
                "config_change",
                "maintenance",
                "system_restart",
            ])

            # Generate realistic change event
            event_data = {
                "source": "cmdb_noise",
                "event_type": "configuration_change",
                "change_type": change_type,
                "asset": f"router-{rng.randint(1, 50):03d}",
                "operator": rng.choice(["alice", "bob", "charlie", "automation"]),
                "approved": rng.random() > 0.1,  # 90% approved
            }

            # Add type-specific details
            if change_type == "software_update":
                event_data["from_version"] = f"9.{rng.randint(0, 5)}.{rng.randint(0, 9)}"
                event_data["to_version"] = f"9.{rng.randint(0, 5)}.{rng.randint(0, 9)}"
            elif change_type == "config_change":
                event_data["config_section"] = rng.choice(["bgp", "ospf", "acl", "interface"])

            events.append((timestamp, event_data))

        return sorted(events, key=lambda x: x[0])
