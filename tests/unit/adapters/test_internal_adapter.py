# tests/test_internal_adapter.py
import pytest

from simulator.output.internal_adapter import InternalAdapter


@pytest.fixture
def adapter() -> InternalAdapter:
    return InternalAdapter()


def test_documentation_event(adapter):
    event = {
        "event_type": "internal.documentation",
        "attributes": {
            "target_prefix": "203.0.113.0/24",
            "target_roa_status": "INVALID",
            "our_prefix": "198.51.100.0/24",
            "our_roa_status": "VALID",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert (
        "[INTERNAL] Target 203.0.113.0/24: INVALID | Our 198.51.100.0/24: VALID"
        in lines[0]
    )


def test_phase_event_waiting(adapter):
    event = {
        "event_type": "internal.phase_event",
        "attributes": {"action": "waiting_period_complete", "days_elapsed": 7},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "[WAITING] 7-day waiting period complete" in lines[0]


def test_phase_event_phase1(adapter):
    event = {
        "event_type": "internal.phase_event",
        "attributes": {"action": "phase1_complete"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "[PHASE] Phase 1 complete: Ready for Phase 2" in lines[0]


def test_monitoring_status(adapter):
    event = {
        "event_type": "internal.monitoring_status",
        "attributes": {"status": "Running", "router": "monitor-router-01"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "[INTERNAL] Status on monitor-router-01: Running" in lines[0]


def test_generic_internal_event(adapter):
    event = {
        "event_type": "internal.unknown_event",
        "attributes": {"action": "something_happened"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "[INTERNAL] something_happened" in lines[0]


def test_generic_internal_event_no_action(adapter):
    event = {
        "event_type": "internal.other_event",
        "attributes": {},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "[INTERNAL] internal.other_event" in lines[0]


def test_unknown_event_type_returns_empty(adapter):
    event = {"event_type": "external_event", "attributes": {}}
    lines = list(adapter.transform(event))
    assert lines == []
