# simulator/feeds/bgp/mock_feed.py
"""
Mock BGP feed for deterministic, offline simulations.

This feed represents a simplified global routing view that can be
queried by scenario telemetry to enrich events with context such as:
- expected origin AS
- normal AS paths
- visibility across collectors
"""

from typing import Any


class MockBGPFeed:
    """
    Simple in-memory representation of baseline BGP state.
    """

    def __init__(self) -> None:
        # prefix -> baseline attributes
        self._routes: dict[str, dict[str, Any]] = {}

    def add_route(
        self,
        prefix: str,
        origin_as: int,
        as_path: list[int],
        collectors: list[str] | None = None,
    ) -> None:
        """
        Register a baseline route as normally observed on the Internet.
        """
        self._routes[prefix] = {
            "origin_as": origin_as,
            "as_path": as_path,
            "collectors": collectors or ["routeviews", "ris"],
        }

    def expected_origin(self, prefix: str) -> int | None:
        """
        Return the normally expected origin AS for a prefix.
        """
        route = self._routes.get(prefix)
        return route["origin_as"] if route else None

    def expected_as_path(self, prefix: str) -> list[int] | None:
        """
        Return the normally observed AS path.
        """
        route = self._routes.get(prefix)
        return route["as_path"] if route else None

    def visibility(self, prefix: str) -> int:
        """
        How many collectors normally see this prefix.
        """
        route = self._routes.get(prefix)
        return len(route["collectors"]) if route else 0

    def is_known_prefix(self, prefix: str) -> bool:
        """
        Whether this prefix exists in baseline routing.
        """
        return prefix in self._routes
