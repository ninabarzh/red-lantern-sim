# tests/unit/adapters/test_rpki_adapter.py
from datetime import UTC, datetime

import pytest

from simulator.output.rpki_adapter import RPKIAdapter


@pytest.fixture
def rpki_adapter():
    return RPKIAdapter()


def _format_ts(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=UTC)
    return dt.strftime("%b %d %H:%M:%S")


def test_rpki_validation_event(rpki_adapter):
    event = {
        "event_type": "rpki.validation",
        "timestamp": 1700000000,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "validation_result": "valid",  # Changed from validation_state
            "roa_exists": True,
        },
        "source": {"observer": "rpki-validator-1"},
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [
        f"<30>{ts_str} rpki-validator-1 RPKI validation: 203.0.113.0/24 origin AS64500 -> valid (ROA exists)"
    ]


def test_rpki_query_event(rpki_adapter):
    event = {
        "event_type": "rpki.query",
        "timestamp": 1700000010,
        "attributes": {
            "prefix": "198.51.100.0/24",
            "origin_as": 64501,
            "query_type": "status_check",
        },
        "source": {},
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    # Default observer is "rpki-validator"
    assert lines == [
        f"<30>{ts_str} rpki-validator RPKI query: 198.51.100.0/24 AS64501 (status_check)"
    ]


def test_roa_creation_event(rpki_adapter):
    event = {
        "event_type": "rpki.roa_creation",
        "timestamp": 1700000020,
        "attributes": {
            "prefix": "192.0.2.0/24",
            "origin_as": 64502,
            "max_length": 28,
            "registry": "ARIN",
            "actor": "operator1",
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [
        f"<29>{ts_str} rpki-validator ROA created for 192.0.2.0/24 (origin AS64502, maxLength /28) via ARIN by operator1"
    ]


def test_roa_published_event(rpki_adapter):
    event = {
        "event_type": "rpki.roa_published",
        "timestamp": 1700000030,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64503,
            "trust_anchor": "RIPE",
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [
        f"<30>{ts_str} rpki-validator RIPE ROA published: 203.0.113.0/24 origin AS64503"
    ]


def test_validator_sync_event(rpki_adapter):
    event = {
        "event_type": "rpki.validator_sync",
        "timestamp": 1700000040,
        "attributes": {
            "prefix": "198.51.100.0/24",
            "origin_as": 64501,  # Added missing field
            "validator": "val1",
            "rpki_state": "valid",
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [
        f"<30>{ts_str} rpki-validator Validator sync: val1 sees 198.51.100.0/24 origin AS64501 -> valid"
    ]


def test_registry_whois_event(rpki_adapter):
    event = {
        "event_type": "registry.whois",
        "timestamp": 1700000050,
        "attributes": {
            "prefix": "192.0.2.0/24",
            "allocated_to": "OrgX",
            "registry": "ARIN",
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [
        f"<30>{ts_str} rpki-validator WHOIS query: 192.0.2.0/24 allocated to OrgX via ARIN"
    ]


def test_internal_documentation_event(rpki_adapter):
    event = {
        "event_type": "internal.documentation",
        "timestamp": 1700000060,
        "attributes": {
            "target_prefix": "203.0.113.0/24",
            "target_roa_status": "valid",
            "our_roa_status": "invalid",
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    # Adapter now outputs simple format for internal events
    assert lines == [f"# {ts_str} internal.documentation"]


def test_internal_phase_transition_event(rpki_adapter):
    event = {
        "event_type": "internal.phase_transition",
        "timestamp": 1700000070,
        "attributes": {"phase": "phase_2", "days_elapsed": 3, "purpose": "testing"},
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    # Adapter now outputs simple format for internal events
    assert lines == [f"# {ts_str} internal.phase_transition"]


def test_internal_phase_complete_event_with_criteria(rpki_adapter):
    event = {
        "event_type": "internal.phase_complete",
        "timestamp": 1700000080,
        "attributes": {
            "phase": "phase_1",
            "ready_for": "next_step",
            "success_criteria": ["criterion1", "criterion2"],
        },
    }
    lines = list(rpki_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    # Adapter now outputs simple format for internal events
    assert lines == [f"# {ts_str} internal.phase_complete"]
