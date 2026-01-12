# tests/unit/adapters/test_monitoring_adapter.py
import pytest

from simulator.output.monitoring_adapter import MonitoringAdapter


@pytest.fixture
def adapter() -> MonitoringAdapter:
    return MonitoringAdapter()


def test_non_monitoring_event_returns_empty(adapter):
    event = {"event_type": "other.event", "attributes": {}}
    lines = list(adapter.transform(event))
    assert lines == []


def test_traffic_performance_event(adapter):
    event = {
        "event_type": "monitoring.anomaly",
        "timestamp": 1767225600,  # Fixed timestamp
        "source": {"observer": "monitor-01"},
        "attributes": {
            "anomaly_type": "traffic_performance",
            "prefix": "203.0.113.0/24",
            "rtt_ms": 50,
            "baseline_ms": 30,
            "packet_loss_pct": 0.5,
            "region": "EMEA",
            "severity": "critical",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "TRAFFIC_ANOMALY" in line
    assert "203.0.113.0/24" in line
    assert "RTT 50ms" in line
    assert "baseline 30ms" in line
    assert "packet loss 0.5%" in line
    assert "EMEA" in line
    # Check priority encoding
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["critical"]) + ">"
    )


def test_service_restored_event_with_note(adapter):
    event = {
        "event_type": "monitoring.anomaly",
        "timestamp": 1767225600,
        "source": {"observer": "monitor-01"},
        "attributes": {
            "anomaly_type": "service_restored",
            "prefix": "198.51.100.0/24",
            "status": "normal",
            "note": "All checks passed",
            "severity": "info",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "SERVICE_RESTORED" in line
    assert "198.51.100.0/24" in line
    assert "normal" in line
    assert "(All checks passed)" in line
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["info"]) + ">"
    )


def test_bgp_route_change_event(adapter):
    event = {
        "event_type": "monitoring.anomaly",
        "timestamp": 1767225600,
        "source": {"observer": "monitor-01"},
        "attributes": {
            "anomaly_type": "bgp_route_change",
            "prefix": "203.0.113.0/24",
            "old_as_path": [64500, 64496],
            "new_as_path": [64500, 64497],
            "change_reason": "manual update",
            "severity": "warning",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "BGP_ROUTE_CHANGE" in line
    assert "203.0.113.0/24" in line
    assert "64500 64496 -> 64500 64497" in line
    assert "manual update" in line
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["warning"]) + ">"
    )


def test_generic_anomaly_event(adapter):
    event = {
        "event_type": "monitoring.anomaly",
        "timestamp": 1767225600,
        "source": {"observer": "monitor-01"},
        "attributes": {
            "anomaly_type": "unknown_type",
            "message": "Custom alert message",
            "severity": "alert",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "Custom alert message" in line
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["alert"]) + ">"
    )


def test_missing_attributes_use_defaults(adapter):
    event = {
        "event_type": "monitoring.anomaly",
        "timestamp": 1767225600,
        "attributes": {},  # No anomaly_type, severity, prefix, etc.
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "unknown" in line  # Default anomaly_type/prefix
    # Default severity is warning
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["warning"]) + ">"
    )
