"""RPKI output adapter for red-lantern-sim.

Transforms RPKI-related events (validation, queries, ROA operations) into syslog-like lines.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from .base import Adapter


class RPKIAdapter(Adapter):
    """Transform RPKI events into syslog-like lines."""

    FACILITY = 3  # System daemons

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")

        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        attr = event.get("attributes", {})
        source = event.get("source", {})
        observer = source.get("observer", "rpki-validator")

        if event_type == "rpki.validation":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            state = attr.get("validation_state", "unknown")
            roa_exists = attr.get("roa_exists")

            if roa_exists is not None:
                msg = f"RPKI validation: {prefix} origin AS{origin_as} -> {state} (ROA {'exists' if roa_exists else 'not found'})"
            else:
                msg = f"RPKI validation: {prefix} origin AS{origin_as} -> {state}"

            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "rpki.query":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            query_type = attr.get("query_type", "status_check")

            msg = f"RPKI query: {prefix} AS{origin_as} ({query_type})"
            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "rpki.roa_creation":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            max_length = attr.get("max_length")
            registry = attr.get("registry")
            actor = attr.get("actor", "unknown")

            msg = f"ROA creation request: {prefix} origin AS{origin_as} maxLength /{max_length} by {actor} via {registry}"
            pri = self.FACILITY * 8 + 5  # notice
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "rpki.roa_published":
            prefix = attr.get("prefix")
            origin_as = attr.get("origin_as")
            trust_anchor = attr.get("trust_anchor")

            msg = f"ROA published: {prefix} origin AS{origin_as} in {trust_anchor} repository"
            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "rpki.validator_sync":
            prefix = attr.get("prefix")
            validator = attr.get("validator")
            rpki_state = attr.get("rpki_state")

            msg = f"Validator sync: {validator} sees {prefix} as {rpki_state}"
            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "registry.whois":
            prefix = attr.get("prefix")
            allocated_to = attr.get("allocated_to")
            registry = attr.get("registry")

            msg = f"WHOIS query: {prefix} allocated to {allocated_to} via {registry}"
            pri = self.FACILITY * 8 + 6  # info
            lines.append(f"<{pri}>{ts_str} {observer} {msg}")

        elif event_type == "internal.documentation":
            # Internal events - output as comment-style lines in training mode
            target_prefix = attr.get("target_prefix")
            target_status = attr.get("target_roa_status")
            our_status = attr.get("our_roa_status")

            msg = f"[BASELINE] Target {target_prefix}: {target_status} | Our status: {our_status}"
            lines.append(f"# {ts_str} {msg}")

        elif event_type == "internal.phase_transition":
            phase = attr.get("phase")
            days = attr.get("days_elapsed")
            purpose = attr.get("purpose", "")

            msg = f"[PHASE] {phase}: {days} days elapsed - {purpose}"
            lines.append(f"# {ts_str} {msg}")

        elif event_type == "internal.phase_complete":
            phase = attr.get("phase")
            ready_for = attr.get("ready_for")

            # Build detailed message based on phase
            if phase == "phase_3":
                hijack_duration = attr.get("hijack_duration_minutes")
                rpki_status = attr.get("rpki_validation_status")
                control_plane = attr.get("control_plane_attack_confirmed")
                msg = f"[COMPLETE] {phase} success - {hijack_duration}min sustained, RPKI: {rpki_status}, control-plane confirmed: {control_plane}"
            else:
                msg = f"[COMPLETE] {phase} success. Ready for: {ready_for}"

            lines.append(f"# {ts_str} {msg}")

            # Add success criteria if present
            criteria = attr.get("success_criteria", [])
            for criterion in criteria:
                lines.append(f"#   ✓ {criterion}")

        return lines
