# tests/unit/adapters/test_tacacs_adapter.py

from datetime import datetime, timezone
import pytest
from simulator.output.tacacs_adapter import TACACSAdapter

@pytest.fixture
def tacacs_adapter():
    return TACACSAdapter()

def _format_ts(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S")

def test_access_login_minimal(tacacs_adapter):
    event = {
        "event_type": "access.login",
        "timestamp": 1700000000,
        "attributes": {}
    }
    lines = list(tacacs_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    # Default user is "unknown", no source_ip, no location
    assert lines == [f"{ts_str} tacacs-server unknown login"]

def test_access_login_with_source_and_location(tacacs_adapter):
    event = {
        "event_type": "access.login",
        "timestamp": 1700000010,
        "attributes": {
            "user": "alice",
            "source_ip": "192.0.2.1",
            "location": "Amsterdam"
        }
    }
    lines = list(tacacs_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} tacacs-server alice login from 192.0.2.1 (Amsterdam)"]

def test_access_logout_minimal(tacacs_adapter):
    event = {
        "event_type": "access.logout",
        "timestamp": 1700000020,
        "attributes": {}
    }
    lines = list(tacacs_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} tacacs-server unknown logout"]

def test_access_logout_with_source_and_location(tacacs_adapter):
    event = {
        "event_type": "access.logout",
        "timestamp": 1700000030,
        "attributes": {
            "user": "bob",
            "source_ip": "198.51.100.5",
            "location": "London"
        }
    }
    lines = list(tacacs_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} tacacs-server bob logout from 198.51.100.5 (London)"]

def test_irrelevant_event_is_ignored(tacacs_adapter):
    event = {
        "event_type": "network.change",
        "timestamp": 1700000040,
        "attributes": {
            "user": "eve"
        }
    }
    lines = list(tacacs_adapter.transform(event))
    assert lines == []  # No output for non-login/logout events
