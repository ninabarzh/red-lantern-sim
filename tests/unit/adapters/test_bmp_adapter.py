# tests/unit/adapters/test_bmp_adapter.py
from __future__ import annotations
import pytest
from simulator.output.bmp_adapter import BMPAdapter


class TestBMPAdapter:
    @pytest.fixture
    def adapter(self) -> BMPAdapter:
        return BMPAdapter()

    def test_transform_full_bgp_update(self, adapter):
        event = {
            "event_type": "bmp_route_monitoring",
            "bgp_update": {
                "prefix": "203.0.113.0/24",
                "as_path": [64500, 174, 6939],
                "next_hop": "198.32.176.1",
                "origin_as": 64500,
            },
            "metadata": {"source": "route-views"},
        }

        lines = list(adapter.transform(event))
        assert len(lines) == 1

        line = lines[0]
        assert "BMP ROUTE:" in line
        assert "prefix 203.0.113.0/24" in line
        assert "AS_PATH [64500, 174, 6939]" in line
        assert "NEXT_HOP 198.32.176.1" in line
        assert "ORIGIN_AS 64500" in line

    def test_transform_partial_bgp_update(self, adapter):
        event = {
            "event_type": "bmp_route_monitoring",
            "bgp_update": {
                "prefix": "198.51.100.0/24",
                "next_hop": "192.0.2.1",
            },
        }

        lines = list(adapter.transform(event))
        assert len(lines) == 1

        line = lines[0]
        assert "prefix 198.51.100.0/24" in line
        assert "AS_PATH []" in line
        assert "NEXT_HOP 192.0.2.1" in line
        assert "ORIGIN_AS 0" in line

    def test_transform_empty_bgp_update(self, adapter):
        event = {
            "event_type": "bmp_route_monitoring",
            "bgp_update": {},
        }

        lines = list(adapter.transform(event))
        assert len(lines) == 1

        line = lines[0]
        assert "prefix unknown" in line
        assert "AS_PATH []" in line
        assert "NEXT_HOP unknown" in line
        assert "ORIGIN_AS 0" in line

    def test_transform_no_bgp_update_field(self, adapter):
        event = {
            "event_type": "bmp_route_monitoring",
        }

        lines = list(adapter.transform(event))
        assert len(lines) == 1

        line = lines[0]
        assert "prefix unknown" in line
        assert "AS_PATH []" in line
        assert "NEXT_HOP unknown" in line
        assert "ORIGIN_AS 0" in line

    def test_transform_unsupported_event_type(self, adapter):
        event = {
            "event_type": "something_else",
            "bgp_update": {"prefix": "192.0.2.0/24"},
        }

        lines = list(adapter.transform(event))
        assert lines == []

    def test_withdrawal_event(self, adapter):
        event = {
            "event_type": "bmp_route_monitoring",
            "bgp_update": {
                "prefix": "203.0.113.0/24",
                "origin_as": 64500,
                "is_withdraw": True,
            },
        }

        lines = list(adapter.transform(event))
        assert len(lines) == 1
        assert "BGP withdrawal" in lines[0]

    def test_withdrawal_complete_event(self, adapter):
        event = {"event_type": "bgp.withdrawal_complete"}
        lines = list(adapter.transform(event))
        assert len(lines) == 1
        assert "withdrawal complete" in lines[0]

    def test_reconvergence_event(self, adapter):
        event = {"event_type": "bgp.reconvergence"}
        lines = list(adapter.transform(event))
        assert len(lines) == 1
        assert "reconvergence completed" in lines[0]
