"""
Unit tests for BMP telemetry generator.
"""

import pytest

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bmp_telemetry import BMPTelemetryGenerator


def test_bmp_generator_initialization():
    """Test BMPTelemetryGenerator can be initialized."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(
        scenario_id="S1",
        scenario_name="test_scenario",
        clock=clock,
        event_bus=event_bus,
    )

    assert generator.clock == clock
    assert generator.event_bus == event_bus
    assert generator.scenario_name == "test_scenario"
    assert generator.scenario_id == "S1"


def test_bmp_route_monitoring_event():
    """Test emit_route_monitoring generates correct event structure."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(
        scenario_id="S2", scenario_name="test_hijack", clock=clock, event_bus=event_bus
    )

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # Emit a route monitoring event
    generator.generate(
        {
            "prefix": "203.0.113.0/24",
            "as_path": [64512, 64500, 64501],
            "origin_as": 64512,
            "next_hop": "192.0.2.1",
            "peer_ip": "192.0.2.1",
            "peer_as": 64512,
            "communities": ["64512:100", "64512:200"],
            "origin": "IGP",
            "is_withdraw": False,
            "scenario": {
                "name": "test_hijack",
                "attack_step": "normal",
                "incident_id": "TEST-001",
            },
        }
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    assert event["event_type"] == "bmp_route_monitoring"
    assert isinstance(event["timestamp"], int)
    assert event["source"]["feed"] == "bmp-collector"
    assert event["source"]["observer"] == "collector-01"

    attributes = event["bgp_update"]
    assert attributes["prefix"] == "203.0.113.0/24"
    assert attributes["as_path"] == [64512, 64500, 64501]
    assert attributes["origin_as"] == 64512
    assert attributes["next_hop"] == "192.0.2.1"
    assert attributes["origin"] == "IGP"
    assert attributes["is_withdraw"] is False
    assert attributes["afi"] == 1
    assert attributes["safi"] == 1

    scenario = event["scenario"]
    assert scenario["name"] == "test_hijack"
    assert scenario["attack_step"] == "normal"
    assert scenario["incident_id"] == "TEST-001"


def test_bmp_route_monitoring_default_scenario():
    """Test generate uses default scenario if not provided."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(
        scenario_id="S3",
        scenario_name="default_scenario",
        clock=clock,
        event_bus=event_bus,
    )

    captured_events = []
    event_bus.subscribe(captured_events.append)

    generator.generate(
        {
            "prefix": "198.51.100.0/24",
            "as_path": [64513, 64502],
            "origin_as": 64513,
            "next_hop": "192.0.2.2",
            "peer_ip": "192.0.2.2",
            "peer_as": 64513,
        }
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    assert event["scenario"]["name"] == "default_scenario"
    assert event["scenario"]["attack_step"] is None
    assert event["scenario"]["incident_id"] is None


def test_bmp_hijack_event():
    """Test generating a hijack event."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(
        scenario_id="S4", scenario_name="hijack_test", clock=clock, event_bus=event_bus
    )

    captured_events = []
    event_bus.subscribe(captured_events.append)

    generator.generate(
        {
            "prefix": "203.0.113.0/24",
            "as_path": [65534, 64503],
            "origin_as": 65534,
            "next_hop": "192.0.2.3",
            "peer_ip": "192.0.2.3",
            "peer_as": 65534,
            "communities": ["65534:666"],
            "origin": "IGP",
            "is_withdraw": False,
        }
    )

    assert len(captured_events) == 1
    event = captured_events[0]
    attributes = event["bgp_update"]

    assert attributes["is_withdraw"] is False
    assert attributes["origin_as"] == 65534
    assert "65534:666" in attributes["communities"]


def test_multiple_bmp_events():
    """Test generating multiple BMP events with proper timestamps."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(
        scenario_id="S5",
        scenario_name="multi_event_test",
        clock=clock,
        event_bus=event_bus,
    )

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # First event at time 0
    generator.generate(
        {
            "prefix": "192.0.2.0/24",
            "as_path": [64512],
            "origin_as": 64512,
            "next_hop": "192.0.2.1",
            "peer_ip": "192.0.2.1",
            "peer_as": 64512,
        }
    )

    clock.advance_to(5)

    # Second event at time 5
    generator.generate(
        {
            "prefix": "203.0.113.0/24",
            "as_path": [64512, 64500],
            "origin_as": 64512,
            "next_hop": "192.0.2.1",
            "peer_ip": "192.0.2.1",
            "peer_as": 64512,
        }
    )

    clock.advance_to(8)

    # Third event at time 8
    generator.generate(
        {
            "prefix": "198.51.100.0/24",
            "as_path": [64513],
            "origin_as": 64513,
            "next_hop": "192.0.2.2",
            "peer_ip": "192.0.2.2",
            "peer_as": 64513,
        }
    )

    assert len(captured_events) == 3
    types = [e["event_type"] for e in captured_events]
    assert types == ["bmp_route_monitoring"] * 3

    timestamps = [e["timestamp"] for e in captured_events]
    assert timestamps == [0, 5, 8]
    assert all(isinstance(ts, int) for ts in timestamps)
