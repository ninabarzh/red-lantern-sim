# simulator/output/bmp_adapter.py
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from .base import Adapter


class BMPAdapter(Adapter):
    """Realistic BMP telemetry adapter matching industry collector formats."""

    FACILITY = 1  # User-level messages
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

    def transform(self, event: dict[str, Any]) -> Iterable[str]:
        """Transform BMP events into realistic collector log lines."""
        lines: list[str] = []

        event_type = event.get("event_type")
        if event_type != "bmp_route_monitoring":
            return lines

        # Get timestamp and format
        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        # Get source/observer
        source = event.get("source", {})
        observer = source.get("observer", "bmp-collector")

        # FIX: Get peer info from peer_header instead of bgp_update
        peer_header = event.get("peer_header", {})
        bgp_update = event.get("bgp_update", {})

        # Extract peer information from peer_header (RFC 7854 compliant)
        peer_ip = peer_header.get("peer_address", "0.0.0.0")
        peer_as = peer_header.get("peer_as", 0)

        # Extract BGP update information
        prefix = bgp_update.get("prefix", "unknown")
        as_path = bgp_update.get("as_path", [])
        next_hop = bgp_update.get("next_hop", "unknown")
        origin_as = bgp_update.get("origin_as", 0)
        is_withdraw = bgp_update.get("is_withdraw", False)

        # Get RPKI state from rpki_validation if present
        rpki_state = None
        rpki_validation = event.get("rpki_validation", {})
        if rpki_validation:
            rpki_state = rpki_validation.get("state")
        # Fallback to bgp_update for backward compatibility
        elif "rpki_state" in bgp_update:
            rpki_state = bgp_update.get("rpki_state")

        if is_withdraw:
            # Standard BMP withdrawal format
            msg = f"PEER_WITHDRAW: peer {peer_ip} AS{peer_as} prefix {prefix}"
            pri = self.FACILITY * 8 + self.SEVERITY_MAP.get("notice", 5)
            lines.append(f"<{pri}>{ts_str} {observer} bmpd: {msg}")
        else:
            # Standard BMP update format
            as_path_str = " ".join(str(asn) for asn in as_path)

            # Build the core message
            msg_parts = [
                f"PEER_UPDATE: peer {peer_ip} AS{peer_as}",
                f"prefix {prefix}",
                f"next-hop {next_hop}",
                f"as-path {as_path_str}",
                f"origin-as {origin_as}",
            ]

            # Add RPKI state if present
            if rpki_state:
                validity_map = {
                    "VALID": "valid",
                    "INVALID": "invalid",
                    "NOT_FOUND": "not-found",
                    "UNKNOWN": "unknown",
                }
                validity = validity_map.get(rpki_state, rpki_state.lower())
                msg_parts.append(f"validity {validity}")

            # Join all parts
            full_msg = " ".join(msg_parts)

            # Use info severity for updates
            pri = self.FACILITY * 8 + self.SEVERITY_MAP.get("info", 6)
            lines.append(f"<{pri}>{ts_str} {observer} bmpd: {full_msg}")

        return lines
