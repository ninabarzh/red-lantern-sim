from __future__ import annotations
from typing import Any, Iterable
import json

from .base import Adapter  # base class for all adapters


class BMPAdapter(Adapter):
    """
    Adapter for BMP telemetry events.

    Converts BMP RouteMonitoring events into strings for CLI or JSON output.
    Matches the pattern used in router_adapter.py and cmdb_adapter.py.
    """

    def transform(self, event: dict[str, Any]) -> Iterable[str]:
        """
        Transform a BMP event dict into output lines.

        Each line is a JSON string representing the BMP event.
        """
        # You could add a concise CLI-friendly line here if desired
        # Example: "BMP ROUTE: prefix 192.0.2.0/24 AS_PATH [65001,65002]"
        bgp_update = event.get("bgp_update", {})
        prefix = bgp_update.get("prefix", "unknown")
        as_path = bgp_update.get("as_path", [])
        next_hop = bgp_update.get("next_hop", "unknown")
        origin_as = bgp_update.get("origin_as", 0)
        malicious = event.get("scenario_metadata", {}).get("is_malicious", False)

        # CLI-friendly line
        line = (
            f"BMP ROUTE: prefix {prefix} AS_PATH {as_path} "
            f"NEXT_HOP {next_hop} ORIGIN_AS {origin_as} "
            f"{'(malicious)' if malicious else ''}"
        )

        # Yield the CLI line
        yield line

        # Also yield JSON representation
        yield json.dumps(event)
