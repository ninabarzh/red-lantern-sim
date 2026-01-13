# tests/unit/adapters/test_bgp_update_adapter.py
from datetime import UTC, datetime

import pytest

from simulator.output.bgp_update_adapter import BGPUpdateAdapter


@pytest.fixture
def adapter() -> BGPUpdateAdapter:
    return BGPUpdateAdapter()


def test_bgp_update_transform(adapter):
    ts = 1767225600  # Jan 1, 2026 00:00:00 UTC
    event = {
        "event_type": "bgp.update",
        "timestamp": ts,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64513,
            "as_path": [64513, 65500],
            "next_hop": "192.0.2.1",
        },
        "scenario": {
            "name": "playbook_test",
            "attack_step": "initial",
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert line.startswith("BGP_CONTROL_PLANE")
    assert "'event_type': 'BGP_UPDATE'" in line
    assert "'prefix': '203.0.113.0/24'" in line
    assert "'origin_as': 64513" in line
    assert "'as_path': [64513, 65500]" in line
    assert "'next_hop': '192.0.2.1'" in line
    assert "'scenario_name': 'playbook_test'" in line
    assert "'attack_step': 'initial'" in line

    # Timestamp check
    expected_ts = datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert expected_ts in line


def test_bgp_withdraw_transform(adapter):
    ts = 1767225600
    event = {
        "event_type": "bgp.withdraw",
        "timestamp": ts,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "withdrawn_by_as": 64513,
        },
        "scenario": {
            "name": "playbook_test",
            "attack_step": "withdraw_phase",
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert line.startswith("BGP_CONTROL_PLANE")
    assert "'event_type': 'BGP_WITHDRAW'" in line
    assert "'prefix': '203.0.113.0/24'" in line
    assert "'withdrawn_by_as': 64513" in line
    assert "'scenario_name': 'playbook_test'" in line
    assert "'attack_step': 'withdraw_phase'" in line


def test_unknown_event_returns_empty(adapter):
    event = {
        "event_type": "bgp.unknown",
        "timestamp": 1767225600,
    }
    lines = list(adapter.transform(event))
    assert lines == []
