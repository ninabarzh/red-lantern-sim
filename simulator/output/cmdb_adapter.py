# simulator/output/cmdb_adapter.py
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timezone

from .base import Adapter


class CMDBAdapter(Adapter):
    """Transform cmdb.change events into syslog-like lines."""

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        if event.get("event_type") != "cmdb.change":
            return lines

        attr = event.get("attributes", {})
        actor = attr.get("actor", "unknown")
        files = attr.get("files_changed", [])
        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%b %d %H:%M:%S")
        msg = f"CMDB change by {actor}, files: {files}"
        lines.append(f"{ts_str} cmdb-server {msg}")
        return lines
