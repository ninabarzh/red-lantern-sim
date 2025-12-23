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

            # Generate files changed
            num_files = rng.randint(1, 5)
            files_changed = [
                f"/etc/router/config_{rng.randint(1, 100)}.conf"
                for _ in range(num_files)
            ]

            # Generate realistic change event matching CMDBAdapter's expected structure
            event_data = {
                "event_type": "cmdb.change",
                "source": "cmdb_noise",
                "attributes": {
                    "actor": rng.choice(["alice", "bob", "charlie", "automation"]),
                    "files_changed": files_changed,
                    "change_type": change_type,
                }
            }

            events.append((timestamp, event_data))

        return sorted(events, key=lambda x: x[0])
