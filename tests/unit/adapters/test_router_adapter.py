# tests/unit/adapters/test_router_adapter.py
from datetime import datetime, timezone
import pytest
from simulator.output.router_adapter import RouterAdapter

@pytest.fixture
def router_adapter():
    return RouterAdapter()

def _format_ts(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S")

@pytest.mark.parametrize(
    "severity,expected_pri",
    [
        ("emergency", 8),
        ("alert", 9),
        ("critical", 10),
        ("error", 11),
        ("warning", 12),
        ("notice", 13),
        ("info", 14),
        ("debug", 15),
        ("unknown", 13),  # default to notice
    ]
)
def test_router_syslog_severity(router_adapter, severity, expected_pri):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1700000000,
        "attributes": {
            "severity": severity,
            "message": "Test message",
            "router": "R2"
        }
    }
    lines = list(router_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"<{expected_pri}>{ts_str} R2 Test message"]

def test_router_syslog_missing_router_defaults_to_r1(router_adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1700000010,
        "attributes": {
            "severity": "info",
            "message": "Router default test"
        }
    }
    lines = list(router_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    pri = RouterAdapter.FACILITY * 8 + RouterAdapter.SEVERITY_MAP["info"]
    assert lines == [f"<{pri}>{ts_str} R1 Router default test"]

def test_irrelevant_event_is_ignored(router_adapter):
    event = {
        "event_type": "bgp.update",  # anything other than router.syslog
        "timestamp": 1700000030,
        "attributes": {
            "message": "should be ignored"
        }
    }
    lines = list(router_adapter.transform(event))
    assert lines == []
