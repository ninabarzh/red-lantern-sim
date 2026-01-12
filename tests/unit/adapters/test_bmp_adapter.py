from datetime import UTC, datetime

from simulator.output.bmp_adapter import BMPAdapter


def _ts(ts: int) -> str:
    """Helper to format timestamps exactly as the adapter does."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%b %d %H:%M:%S")


def test_ignores_non_bmp_events():
    adapter = BMPAdapter()

    event = {
        "event_type": "something_else",
        "timestamp": 1767225600,
    }

    lines = list(adapter.transform(event))
    assert lines == []


def test_basic_bmp_update_without_rpki():
    adapter = BMPAdapter()
    ts = 1767225600

    event = {
        "event_type": "bmp_route_monitoring",
        "timestamp": ts,
        "source": {"observer": "bmp-test"},
        "peer_header": {
            "peer_address": "192.0.2.1",
            "peer_as": 64500,
        },
        "bgp_update": {
            "prefix": "203.0.113.0/24",
            "as_path": [64500, 64496],
            "next_hop": "198.51.100.1",
            "origin_as": 64496,
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert line.startswith("<14>")  # facility 1, severity info (6)
    assert _ts(ts) in line
    assert "bmp-test bmpd:" in line
    assert "PEER_UPDATE: peer 192.0.2.1 AS64500" in line
    assert "prefix 203.0.113.0/24" in line
    assert "next-hop 198.51.100.1" in line
    assert "as-path 64500 64496" in line
    assert "origin-as 64496" in line
    assert "validity" not in line


def test_bmp_update_with_rpki_validation():
    adapter = BMPAdapter()
    ts = 1767225600

    event = {
        "event_type": "bmp_route_monitoring",
        "timestamp": ts,
        "peer_header": {
            "peer_address": "192.0.2.2",
            "peer_as": 64497,
        },
        "bgp_update": {
            "prefix": "198.51.100.0/24",
            "as_path": [64497],
            "next_hop": "192.0.2.254",
            "origin_as": 64497,
        },
        "rpki_validation": {
            "state": "INVALID",
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert "validity invalid" in line


def test_bmp_update_rpki_fallback_to_bgp_update():
    adapter = BMPAdapter()
    ts = 1767225600

    event = {
        "event_type": "bmp_route_monitoring",
        "timestamp": ts,
        "peer_header": {
            "peer_address": "192.0.2.3",
            "peer_as": 64510,
        },
        "bgp_update": {
            "prefix": "10.0.0.0/8",
            "as_path": [64510],
            "next_hop": "192.0.2.1",
            "origin_as": 64510,
            "rpki_state": "VALID",
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert "validity valid" in line


def test_bmp_withdraw_event():
    adapter = BMPAdapter()
    ts = 1767225600

    event = {
        "event_type": "bmp_route_monitoring",
        "timestamp": ts,
        "source": {"observer": "bmp-test"},
        "peer_header": {
            "peer_address": "203.0.113.9",
            "peer_as": 64501,
        },
        "bgp_update": {
            "prefix": "203.0.113.0/24",
            "is_withdraw": True,
        },
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert line.startswith("<13>")  # facility 1, severity notice (5)
    assert _ts(ts) in line
    assert "PEER_WITHDRAW: peer 203.0.113.9 AS64501 prefix 203.0.113.0/24" in line


def test_defaults_are_used_when_fields_missing():
    adapter = BMPAdapter()
    ts = 1767225600

    event = {
        "event_type": "bmp_route_monitoring",
        "timestamp": ts,
    }

    lines = list(adapter.transform(event))
    assert len(lines) == 1

    line = lines[0]
    assert "peer 0.0.0.0 AS0" in line
    assert "prefix unknown" in line
