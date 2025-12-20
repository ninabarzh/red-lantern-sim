"""
Simulation clock for the Red Lantern BGP attack-chain simulator.

This clock exists to decouple scenario execution from wall-clock time.
Scenarios advance deterministically, regardless of how fast or slow the
host system happens to be.

The clock does not sleep. It does not wait. It merely records and
advances simulated time.
"""

from typing import Union


class SimulationClock:
    """
    A minimal simulated clock.

    Time is represented as integer seconds since the start of the
    scenario. No assumptions are made about real-world timestamps.
    """

    def __init__(self) -> None:
        self._current_time: int = 0

    def now(self) -> int:
        """
        Return the current simulated time in seconds.
        """
        return self._current_time

    def advance_to(self, target_time: int | float) -> None:
        """
        Advance the clock to the specified time.

        The clock may only move forwards. Attempting to move backwards is
        treated as a scenario authoring error.
        """
        target = int(target_time)

        if target < self._current_time:
            raise ValueError(
                f"Cannot move clock backwards from {self._current_time} to {target}"
            )

        self._current_time = target

    def reset(self) -> None:
        """
        Reset the clock to time zero.
        """
        self._current_time = 0
