# simulator/output/internal_adapter.py
from typing import Iterable
from .base import Adapter  # assuming Adapter base class exists

class InternalAdapter(Adapter):
    """Print internal events to CLI in a readable, non-syslog form."""

    def transform(self, event: dict) -> Iterable[str]:
        lines = []
        etype = event.get("event_type", "unknown")
        attrs = event.get("attributes", {})

        if etype == "internal.monitoring_status":
            status = attrs.get("status", "OK")
            router = attrs.get("router", "edge-router-01")
            lines.append(f"[INTERNAL] Monitoring status on {router}: {status}")

        elif etype == "internal.phase_complete":
            phase = attrs.get("phase", "unknown")
            lines.append(f"[INTERNAL] Phase complete: {phase}")

        elif etype.startswith("internal."):
            # generic fallback for other internal events
            lines.append(f"[INTERNAL] {etype}: {attrs}")

        return lines
