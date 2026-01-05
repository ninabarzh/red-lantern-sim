# simulator/output/router_adapter.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from .base import Adapter

class RouterAdapter(Adapter):
    """Transform router.syslog events into syslog-like lines."""

    SEVERITY_MAP = {
        "emergency": 0, "alert": 1, "critical": 2, "error": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7
    }

    FACILITY = 1

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")
        if event_type != "router.syslog":
            return lines

        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        attr = event.get("attributes", {})
        severity = attr.get("severity", "notice")
        msg = attr.get("message", "")
        router = attr.get("router", "R1")

        pri = self.FACILITY * 8 + self.SEVERITY_MAP.get(severity, 5)
        line = f"<{pri}>{ts_str} {router} {msg}"
        lines.append(line)

        return lines
