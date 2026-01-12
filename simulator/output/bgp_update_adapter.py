"""
Adapter for raw BGP control-plane update events.
These events are not typically sent to syslog but could be formatted as structured data.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from .base import Adapter


class BGPUpdateAdapter(Adapter):
    """Transforms raw BGP update events for structured logging."""

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")

        if event_type not in ("bgp.update", "bgp.withdraw"):
            return lines

        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # ISO format for structured logs

        attr = event.get("attributes", {})
        scenario = event.get("scenario", {})

        if event_type == "bgp.update":
            # Format as a structured JSON-like log line for SIEM ingestion
            # In practice, this could be pure JSON. This is a readable compromise.
            log_dict = {
                "timestamp": ts_str,
                "event_type": "BGP_UPDATE",
                "prefix": attr.get("prefix"),
                "origin_as": attr.get("origin_as"),
                "as_path": attr.get("as_path", []),
                "next_hop": attr.get("next_hop"),
                "scenario_name": scenario.get("name"),
                "attack_step": scenario.get("attack_step"),
            }
            lines.append(f"BGP_CONTROL_PLANE {log_dict}")

        elif event_type == "bgp.withdraw":
            log_dict = {
                "timestamp": ts_str,
                "event_type": "BGP_WITHDRAW",
                "prefix": attr.get("prefix"),
                "withdrawn_by_as": attr.get("withdrawn_by_as"),
                "scenario_name": scenario.get("name"),
                "attack_step": scenario.get("attack_step"),
            }
            lines.append(f"BGP_CONTROL_PLANE {log_dict}")

        return lines
