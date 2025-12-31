from __future__ import annotations
from typing import Any, Iterable
import json

from .base import Adapter


class BMPAdapter(Adapter):
    """Adapter for BMP telemetry events."""

    def transform(self, event: dict[str, Any]) -> Iterable[str]:
        lines: list[str] = []

        bgp_update = event.get("bgp_update", {})
        prefix = bgp_update.get("prefix", "unknown")
        as_path = bgp_update.get("as_path", [])
        next_hop = bgp_update.get("next_hop", "unknown")
        origin_as = bgp_update.get("origin_as", 0)

        # CLI-friendly line
        line = (
            f"BMP ROUTE: prefix {prefix} AS_PATH {as_path} "
            f"NEXT_HOP {next_hop} ORIGIN_AS {origin_as}"
        )
        lines.append(line)

        # JSON representation
        lines.append(json.dumps(event))

        return lines
