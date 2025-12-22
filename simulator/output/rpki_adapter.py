# simulator/output/rpki_adapter.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from .base import Adapter

class RPKIAdapter(Adapter):
    """Transform rpki.validation events into syslog-like lines."""

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        if event.get("event_type") != "rpki.validation":
            return lines

        attr = event.get("attributes", {})
        prefix = attr.get("prefix")
        origin_as = attr.get("origin_as")
        state = attr.get("validation_state", "unknown")
        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_str = dt.strftime("%b %d %H:%M:%S")
        msg = f"RPKI validation: {prefix} origin AS{origin_as} -> {state}"
        lines.append(f"{ts_str} rpki-validator {msg}")
        return lines
