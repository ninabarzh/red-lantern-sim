# simulator/output/router_adapter.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from .base import Adapter

class RouterAdapter(Adapter):
    """Transform router.syslog and bgp.update events into syslog-like lines."""

    SEVERITY_MAP = {
        "emergency": 0, "alert": 1, "critical": 2, "error": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7
    }

    FACILITY = 1

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")
        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        if event_type == "router.syslog":
            attr = event.get("attributes", {})
            severity = attr.get("severity", "notice")
            msg = attr.get("message", "")
            pri = self.FACILITY * 8 + self.SEVERITY_MAP.get(severity, 5)
            line = f"<{pri}>{ts_str} {attr.get('router','R1')} {msg}"
            lines.append(line)

        elif event_type == "bgp.update":
            attr = event.get("attributes", {})
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            as_path = attr.get("as_path", [])
            next_hop = attr.get("next_hop")
            msg = f"%BGP-5-UPDATE: {prefix} via AS{origin_as}, next-hop {next_hop}, path {as_path}"
            pri = self.FACILITY * 8 + self.SEVERITY_MAP.get("notice", 5)
            lines.append(f"<{pri}>{ts_str} R1 {msg}")

        return lines
