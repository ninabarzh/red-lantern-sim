# simulator/output/router_adapter.py
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from .base import Adapter


class RouterAdapter(Adapter):
    """Transform router.syslog events into syslog-like lines."""

    SEVERITY_MAP = {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5,
        "info": 6,
        "debug": 7,
    }

    FACILITY = 1

    def _format_message(self, attr: dict) -> str:
        """Format structured data into log message."""
        # BGP neighbor state change
        if attr.get("bgp_event") == "neighbor_state_change":
            peer_ip = attr.get("peer_ip", "unknown")
            state = attr.get("neighbor_state", "unknown")
            reason = attr.get("change_reason", "")

            if state == "up":
                return f"BGP: %BGP-5-ADJCHANGE: neighbor {peer_ip} Up"
            elif state == "down":
                reason_part = f": {reason}" if reason else ""
                return f"BGP: %BGP-5-ADJCHANGE: neighbor {peer_ip} Down{reason_part}"
            else:
                return f"BGP: neighbor {peer_ip} state changed to {state}"

        # Configuration change
        elif attr.get("config_event") == "change":
            user = attr.get("changed_by", "unknown")
            change_type = attr.get("change_type", "")
            target = attr.get("change_target", "")

            if change_type == "roa_request":
                return f"Configuration change by {user}: ROA request for {target}"
            else:
                return f"Configuration change by {user}: {target}"

        # Fallback to message field for backward compatibility
        return attr.get("message", "")

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")
        if event_type != "router.syslog":
            return lines

        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        attr = event.get("attributes", {})
        severity = attr.get("severity", "notice")
        router = attr.get("router", "R1")

        # FORMAT from structured data
        msg = self._format_message(attr)

        pri = self.FACILITY * 8 + self.SEVERITY_MAP.get(severity, 5)
        line = f"<{pri}>{ts_str} {router} {msg}"
        lines.append(line)

        return lines
