from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .base import Adapter


class BMPAdapter(Adapter):
    """Adapter for BMP telemetry events, including withdrawals and reconvergence."""

    def transform(self, event: dict[str, Any]) -> Iterable[str]:
        lines: list[str] = []

        event_type = event.get("event_type")
        bgp_update = event.get("bgp_update", {})

        if event_type == "bmp_route_monitoring":
            prefix = bgp_update.get("prefix", "unknown")
            as_path = bgp_update.get("as_path", [])
            next_hop = bgp_update.get("next_hop", "unknown")
            origin_as = bgp_update.get("origin_as", 0)
            is_withdraw = bgp_update.get("is_withdraw", False)

            if is_withdraw:
                line = f"<13>Jan 01 01:32:00 edge-router-01 BGP withdrawal: {prefix} from AS{origin_as}"
            else:
                line = (
                    f"BMP ROUTE: prefix {prefix} AS_PATH {as_path} "
                    f"NEXT_HOP {next_hop} ORIGIN_AS {origin_as}"
                )
            lines.append(line)

        elif event_type == "bgp.withdrawal_complete":
            # Minimal placeholder for demonstration
            lines.append("<13>Jan 01 01:32:10 edge-router-01 BGP withdrawal complete")

        elif event_type == "bgp.reconvergence":
            lines.append(
                "<14>Jan 01 01:35:00 edge-router-01 BGP reconvergence completed"
            )

        return lines
