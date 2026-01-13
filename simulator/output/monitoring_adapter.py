# simulator/output/monitoring_adapter.py
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from .base import Adapter


class MonitoringAdapter(Adapter):
    """Adapter for network monitoring system logs (nagios, zabbix, librenms, etc.)."""

    FACILITY = 3  # System daemons (same as RPKI)
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

    def transform(self, event: dict) -> Iterable[str]:
        lines: list[str] = []
        event_type = event.get("event_type")

        if event_type != "monitoring.anomaly":
            return lines

        # Get timestamp
        ts = event.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        ts_str = dt.strftime("%b %d %H:%M:%S")

        # Get source/observer
        source = event.get("source", {})
        observer = source.get("observer", "netsys-monitor")

        # Get attributes
        attr = event.get("attributes", {})
        anomaly_type = attr.get("anomaly_type", "unknown")
        prefix = attr.get("prefix", "unknown")
        severity = attr.get("severity", "warning")

        # Map severity to numeric
        severity_num = self.SEVERITY_MAP.get(severity, 4)  # default to warning

        # Calculate priority
        pri = self.FACILITY * 8 + severity_num

        # Format based on anomaly type
        if anomaly_type == "traffic_performance":
            rtt_ms = attr.get("rtt_ms", 0)
            baseline_ms = attr.get("baseline_ms", 0)
            packet_loss = attr.get("packet_loss_pct", 0.0)
            region = attr.get("region", "unknown")

            message = (
                f"TRAFFIC_ANOMALY: {prefix} RTT {rtt_ms}ms "
                f"(baseline {baseline_ms}ms), packet loss {packet_loss}%, region {region}"
            )
            lines.append(f"<{pri}>{ts_str} {observer} {message}")

        elif anomaly_type == "service_restored":
            status = attr.get("status", "normal")
            note = attr.get("note", "")

            message = f"SERVICE_RESTORED: {prefix} {status}"
            if note:
                message += f" ({note})"
            lines.append(f"<{pri}>{ts_str} {observer} {message}")

        elif anomaly_type == "bgp_route_change":
            old_path = attr.get("old_as_path", [])
            new_path = attr.get("new_as_path", [])
            reason = attr.get("change_reason", "unknown")

            old_str = " ".join(str(x) for x in old_path)
            new_str = " ".join(str(x) for x in new_path)
            message = f"BGP_ROUTE_CHANGE: {prefix} path changed {old_str} -> {new_str} ({reason})"
            lines.append(f"<{pri}>{ts_str} {observer} {message}")

        else:
            # Generic monitoring event
            message = attr.get("message", f"Monitoring event: {anomaly_type}")
            lines.append(f"<{pri}>{ts_str} {observer} {message}")

        return lines
