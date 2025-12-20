"""
Telemetry generators for the Red Lantern simulator.

Provides structured telemetry to complement scenario events.

Generators included:
- BGPUpdateGenerator: emits BGP UPDATE and WITHDRAW events
- RouterSyslogGenerator: emits router-style syslog messages
- LatencyMetricsGenerator: emits latency and jitter metrics
"""

from telemetry.generators.bgp_updates import BGPUpdateGenerator
from telemetry.generators.latency_metrics import LatencyMetricsGenerator
from telemetry.generators.router_syslog import RouterSyslogGenerator

__all__ = [
    "BGPUpdateGenerator",
    "RouterSyslogGenerator",
    "LatencyMetricsGenerator",
]
