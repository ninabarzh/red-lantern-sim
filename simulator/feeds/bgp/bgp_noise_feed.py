"""
Background BGP noise feed.

Generates realistic, ongoing BGP churn to simulate normal Internet
routing behavior. These events run continuously alongside attack scenarios.
"""

import random
from typing import Any

from simulator.engine.simulation_engine import BackgroundFeed


class BGPNoiseFeed(BackgroundFeed):
    """
    Produces background BGP UPDATE events.

    Simulates normal Internet churn:
    - Prefix announcements
    - Withdrawals
    - Path changes
    """

    def __init__(self, update_rate: float = 0.5, seed: int = 42):
        """
        Args:
            update_rate: Average BGP updates per second
            seed: Random seed for determinism
        """
        self.update_rate = update_rate
        self.seed = seed

    def generate_events(self, duration: int) -> list[tuple[int, dict[str, Any]]]:
        """
        Generate deterministic background BGP events.

        Args:
            duration: Simulation duration in seconds

        Returns:
            List of (timestamp, event_dict) tuples
        """
        rng = random.Random(self.seed)

        # Calculate total events
        total_events = int(duration * self.update_rate)

        events = []

        for _ in range(total_events):
            # Random timestamp within duration
            timestamp = rng.randint(0, duration)

            # Generate realistic BGP update
            event_data = {
                "source": "bgp_noise",
                "event_type": "bgp_update",
                "prefix": self._random_prefix(rng),
                "origin_as": rng.randint(1000, 65000),
                "as_path": self._random_as_path(rng),
                "update_type": rng.choice(["announce", "withdraw"]),
                "collector": rng.choice(["routeviews", "ris"]),
            }

            events.append((timestamp, event_data))

        return sorted(events, key=lambda x: x[0])

    def _random_prefix(self, rng: random.Random) -> str:
        """Generate a random IP prefix."""
        octet1 = rng.randint(1, 223)
        octet2 = rng.randint(0, 255)
        octet3 = rng.randint(0, 255)
        prefix_len = rng.choice([24, 23, 22, 21, 20, 19, 16])
        return f"{octet1}.{octet2}.{octet3}.0/{prefix_len}"

    def _random_as_path(self, rng: random.Random) -> list[int]:
        """Generate a random AS path."""
        path_length = rng.randint(2, 6)
        return [rng.randint(1000, 65000) for _ in range(path_length)]
