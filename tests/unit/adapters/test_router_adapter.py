# tests/unit/adapters/test_router_adapter.py
import pytest

from simulator.output.router_adapter import RouterAdapter


@pytest.fixture
def adapter() -> RouterAdapter:
    return RouterAdapter()


def test_non_router_event_returns_empty(adapter):
    event = {"event_type": "other.event", "attributes": {}}
    lines = list(adapter.transform(event))
    assert lines == []


def test_bgp_neighbor_state_up(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {
            "bgp_event": "neighbor_state_change",
            "peer_ip": "192.0.2.1",
            "neighbor_state": "up",
            "severity": "info",
            "router": "edge-router-01",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "BGP: %BGP-5-ADJCHANGE: neighbor 192.0.2.1 Up" in line
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["info"]) + ">"
    )
    assert "edge-router-01" in line


def test_bgp_neighbor_state_down_with_reason(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {
            "bgp_event": "neighbor_state_change",
            "peer_ip": "192.0.2.2",
            "neighbor_state": "down",
            "change_reason": "administratively down",
            "severity": "warning",
            "router": "edge-router-02",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert (
        "BGP: %BGP-5-ADJCHANGE: neighbor 192.0.2.2 Down: administratively down" in line
    )
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["warning"]) + ">"
    )
    assert "edge-router-02" in line


def test_bgp_neighbor_unknown_state(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {
            "bgp_event": "neighbor_state_change",
            "peer_ip": "192.0.2.3",
            "neighbor_state": "flapping",
            "severity": "error",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "neighbor 192.0.2.3 state changed to flapping" in lines[0]
    assert lines[0].startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["error"]) + ">"
    )


def test_configuration_change_roa_request(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {
            "config_event": "change",
            "changed_by": "admin",
            "change_type": "roa_request",
            "change_target": "203.0.113.0/24",
            "severity": "info",
            "router": "edge-router-03",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "Configuration change by admin: ROA request for 203.0.113.0/24" in line
    assert "edge-router-03" in line
    assert line.startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["info"]) + ">"
    )


def test_configuration_change_generic(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {
            "config_event": "change",
            "changed_by": "operator",
            "change_target": "interface Gig0/1",
            "severity": "notice",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "Configuration change by operator: interface Gig0/1" in lines[0]
    # Default router name
    assert "R1" in lines[0]
    assert lines[0].startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["notice"]) + ">"
    )


def test_fallback_message(adapter):
    event = {
        "event_type": "router.syslog",
        "timestamp": 1767225600,
        "attributes": {"message": "Custom syslog message", "severity": "debug"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "Custom syslog message" in lines[0]
    assert lines[0].startswith(
        "<" + str(adapter.FACILITY * 8 + adapter.SEVERITY_MAP["debug"]) + ">"
    )
