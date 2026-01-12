# simulator/output/internal_adapter.py
from collections.abc import Iterable

from .base import Adapter


class InternalAdapter(Adapter):
    """Print internal events to CLI in a readable, non-syslog form."""

    def transform(self, event: dict) -> Iterable[str]:
        lines = []
        etype = event.get("event_type", "unknown")
        attrs = event.get("attributes", {})

        if etype == "internal.documentation":
            # Format baseline documentation nicely
            target_prefix = attrs.get("target_prefix", "unknown")
            target_status = attrs.get("target_roa_status", "unknown")
            our_prefix = attrs.get("our_prefix", "unknown")
            our_status = attrs.get("our_roa_status", "unknown")

            lines.append(
                f"[INTERNAL] Target {target_prefix}: {target_status} | Our {our_prefix}: {our_status}"
            )

        elif etype == "internal.phase_event":
            action = attrs.get("action", "unknown")
            if action == "waiting_period_complete":
                days = attrs.get("days_elapsed", 0)
                lines.append(f"[WAITING] {days}-day waiting period complete")
            elif action == "phase1_complete":
                lines.append("[PHASE] Phase 1 complete: Ready for Phase 2")

        elif etype == "internal.monitoring_status":
            status = attrs.get("status", "OK")
            router = attrs.get("router", "edge-router-01")
            lines.append(f"[INTERNAL] Status on {router}: {status}")

        elif etype.startswith("internal."):
            # Generic fallback - clean up the output
            action = attrs.get("action", etype)
            lines.append(f"[INTERNAL] {action}")

        return lines
