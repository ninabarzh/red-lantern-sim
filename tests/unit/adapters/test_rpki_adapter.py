# tests/test_rpki_adapter.py
import pytest

from simulator.output.rpki_adapter import RPKIAdapter


@pytest.fixture
def adapter() -> RPKIAdapter:
    return RPKIAdapter()


def test_roa_creation_accepted(adapter):
    event = {
        "event_type": "rpki.roa_creation",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "registry": "RIPE",
            "status": "accepted",
        },
        "source": {"observer": "rpki-validator"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "ROA accepted for 203.0.113.0/24 AS64500 via RIPE" in line
    assert line.startswith("<" + str(adapter.FACILITY * 8 + 5) + ">")


def test_roa_creation_with_max_length(adapter):
    event = {
        "event_type": "rpki.roa_creation",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "198.51.100.0/24",
            "origin_as": 64496,
            "max_length": 28,
            "registry": "ARIN",
            "actor": "operator",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert (
        "ROA created for 198.51.100.0/24 (origin AS64496, maxLength /28) via ARIN by operator"
        in line
    )
    assert line.startswith("<" + str(adapter.FACILITY * 8 + 5) + ">")


def test_roa_published(adapter):
    event = {
        "event_type": "rpki.roa_published",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "trust_anchor": "RIPE",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    line = lines[0]
    assert "RIPE ROA published: 203.0.113.0/24 origin AS64500" in line
    assert line.startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_validator_sync_with_revalidation(adapter):
    event = {
        "event_type": "rpki.validator_sync",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "rpki_state": "VALID",
            "revalidation": True,
            "validator": "rpki-validator-01",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert (
        "RPKI_REVALIDATION: 203.0.113.0/24 AS64500 → VALID (rpki-validator-01)"
        in lines[0]
    )
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_validator_sync_without_revalidation(adapter):
    event = {
        "event_type": "rpki.validator_sync",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "198.51.100.0/24",
            "origin_as": 64496,
            "rpki_state": "INVALID",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    # Uses observer as validator by default
    assert (
        "RPKI_VALIDATION: 198.51.100.0/24 AS64496 → INVALID (rpki-validator)"
        in lines[0]
    )
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_rpki_query_with_result(adapter):
    event = {
        "event_type": "rpki.query",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "validation_result": "VALID",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "RPKI query: 203.0.113.0/24 AS64500 → VALID" in lines[0]
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_rpki_query_without_result(adapter):
    event = {
        "event_type": "rpki.query",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "198.51.100.0/24",
            "origin_as": 64496,
            "query_type": "status_check",
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "RPKI query: 198.51.100.0/24 AS64496 (status_check)" in lines[0]
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_rpki_validation_with_roa_exists(adapter):
    event = {
        "event_type": "rpki.validation",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "origin_as": 64500,
            "validation_result": "VALID",
            "roa_exists": True,
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "(ROA exists)" in lines[0]
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_registry_whois(adapter):
    event = {
        "event_type": "registry.whois",
        "timestamp": 1767225600,
        "attributes": {
            "prefix": "203.0.113.0/24",
            "allocated_to": "Example Org",
            "registry": "RIPE",
            "origin_as": 64500,
        },
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert "WHOIS_QUERY: 203.0.113.0/24 → 'Example Org' AS64500 (RIPE)" in lines[0]
    assert lines[0].startswith("<" + str(adapter.FACILITY * 8 + 6) + ">")


def test_internal_event(adapter):
    event = {
        "event_type": "internal.debug_event",
        "timestamp": 1767225600,
        "attributes": {"message": "Debug info"},
    }
    lines = list(adapter.transform(event))
    assert len(lines) == 1
    assert lines[0].startswith("#")
    assert "Debug info" in lines[0]
