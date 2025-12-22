# simulator/output/tacacs_adapter.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from .base import Adapter

class TACACSAdapter(Adapter):
    """Transform access.login/logout events into realistic TACACS syslog lines."""

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")
        if event_type not in ("access.login", "access.logout"):
            return lines

        attr = event.get("attributes", {})
        user = attr.get("user", "unknown")
        source_ip = attr.get("source_ip")
        location = attr.get("location")
        action = "login" if event_type == "access.login" else "logout"
        ts = event.get("timestamp", 0)

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        msg = f"{ts_str} tacacs-server {user} {action}"
        if source_ip:
            msg += f" from {source_ip}"
        if location:
            msg += f" ({location})"

        lines.append(msg)
        return lines
