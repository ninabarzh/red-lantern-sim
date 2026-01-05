# tests/unit/adapters/test_bmp_adapter.py
from __future__ import annotations
import json
import pytest
from simulator.output.bmp_adapter import BMPAdapter


class TestBMPAdapter:
    @pytest.fixture
    def adapter(self) -> BMPAdapter:
        return BMPAdapter()

    def test_transform_full_bgp_update(self, adapter):
        event = {
            "bgp_update": {
                "prefix": "203.0.113.0/24",
                "as_path": [64500, 174, 6939],
                "next_hop": "198.32.176.1",
                "origin_as": 64500
            },
            "metadata": {"source": "route-views"}
        }
        lines = list(adapter.transform(event))
        assert len(lines) == 2

        cli_line = lines[0]
        assert "BMP ROUTE:" in cli_line
        assert "prefix 203.0.113.0/24" in cli_line
        assert "AS_PATH [64500, 174, 6939]" in cli_line
        assert "NEXT_HOP 198.32.176.1" in cli_line
        assert "ORIGIN_AS 64500" in cli_line

        json_line = lines[1]
        parsed = json.loads(json_line)
        assert parsed == event

    def test_transform_partial_bgp_update(self, adapter):
        event = {
            "bgp_update": {
                "prefix": "198.51.100.0/24",
                "next_hop": "192.0.2.1"
            }
        }
        lines = list(adapter.transform(event))
        assert len(lines) == 2

        cli_line = lines[0]
        assert "prefix 198.51.100.0/24" in cli_line
        assert "AS_PATH []" in cli_line  # default empty list
        assert "NEXT_HOP 192.0.2.1" in cli_line
        assert "ORIGIN_AS 0" in cli_line  # default 0

    def test_transform_empty_bgp_update(self, adapter):
        event = {"bgp_update": {}}
        lines = list(adapter.transform(event))
        assert len(lines) == 2
        cli_line = lines[0]
        assert "prefix unknown" in cli_line
        assert "AS_PATH []" in cli_line
        assert "NEXT_HOP unknown" in cli_line
        assert "ORIGIN_AS 0" in cli_line

    def test_transform_no_bgp_update_field(self, adapter):
        event = {"metadata": {"source": "route-views"}}
        lines = list(adapter.transform(event))
        assert len(lines) == 2  # Even without bgp_update, defaults apply
        cli_line = lines[0]
        assert "prefix unknown" in cli_line
        assert "AS_PATH []" in cli_line
        assert "NEXT_HOP unknown" in cli_line
        assert "ORIGIN_AS 0" in cli_line

    def test_transform_extra_fields_preserved_in_json(self, adapter):
        event = {
            "bgp_update": {
                "prefix": "192.0.2.0/24",
                "as_path": [65000, 65100],
                "next_hop": "198.51.100.1",
                "origin_as": 65000
            },
            "metadata": {"collector": "rrc00", "extra": "value"}
        }
        lines = list(adapter.transform(event))
        json_line = lines[1]
        parsed = json.loads(json_line)
        assert parsed["metadata"]["extra"] == "value"
        assert parsed["bgp_update"]["prefix"] == "192.0.2.0/24"
