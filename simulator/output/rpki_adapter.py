# simulator/output/rpki_adapter.py

"""RPKI output adapter for red-lantern-sim.

Transforms RPKI-related events (validation, queries, ROA operations) into syslog-like lines.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from .base import Adapter


class RPKIAdapter(Adapter):
    """Transform RPKI events into realistic syslog-like lines."""

    FACILITY = 3  # System daemons

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")

        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        attr = event.get("attributes", {})
        source = event.get("source", {})
        observer = source.get("observer", "rpki-validator")

        # --- ROA creation ---
        if event_type == "rpki.roa_creation":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            max_length = attr.get("max_length")
            registry = attr.get("registry")
            actor = attr.get("actor", "unknown")

            msg = f"ROA created for {prefix} (origin AS{origin_as}, maxLength /{max_length}) via {registry} by {actor}"
            pri = self.FACILITY * 8 + 5  # notice
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- ROA published to repository ---
        elif event_type == "rpki.roa_published":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            trust_anchor = attr.get("trust_anchor", "arin")
            msg = f"{trust_anchor} ROA published: {prefix} origin AS{origin_as}"
            pri = self.FACILITY * 8 + 6
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- Validator sync ---
        elif event_type == "rpki.validator_sync":
            prefix = attr.get("prefix")
            validator = (
                attr.get("validator") or observer
            )  # Use event's validator or observer as fallback
            rpki_state = attr.get("rpki_state", "unknown")

            # Build realistic sync message
            msg = f"Validator sync: {validator} sees {prefix} origin AS{attr.get('origin_as')} -> {rpki_state}"

            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- Validation query ---
        elif event_type == "rpki.query":
            prefix = attr.get("prefix", "unknown")
            origin_as = attr.get("origin_as", "unknown")
            query_type = attr.get("query_type", "status_check")
            msg = f"RPKI query: {prefix} AS{origin_as} ({query_type})"
            pri = self.FACILITY * 8 + 6
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- Validation results (general) ---
        elif event_type == "rpki.validation":
            prefix = attr.get("prefix", "unknown")
            origin_as = attr.get("origin_as", "unknown")
            state = attr.get("validation_result", "unknown")
            roa_exists = attr.get("roa_exists")
            msg = f"RPKI validation: {prefix} origin AS{origin_as} -> {state}"
            if roa_exists is not None:
                msg += f" (ROA {'exists' if roa_exists else 'not found'})"
            pri = self.FACILITY * 8 + 6
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- WHOIS / registry ---
        elif event_type == "registry.whois":
            prefix = attr.get("prefix")
            allocated_to = attr.get("allocated_to")
            registry = attr.get("registry")
            msg = f"WHOIS query: {prefix} allocated to {allocated_to} via {registry}"
            pri = self.FACILITY * 8 + 6
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        # --- Internal events (optional, training/debug) ---
        elif event_type.startswith("internal."):
            # leave them as-is; cli.py can filter lines starting with "#"
            lines.append(f"# {ts_str} {attr.get('message', event_type)}")

        return lines
