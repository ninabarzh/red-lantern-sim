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
    generator = BMPTelemetryGenerator(clock, event_bus, "test_scenario")

    assert generator.clock == clock
    assert generator.event_bus == event_bus
    assert generator.scenario_name == "test_scenario"


def test_bmp_route_monitoring_event():
    """Test emit_route_monitoring generates correct event structure."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "test_hijack")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # Emit a route monitoring event
    generator.emit_route_monitoring(
        prefix="203.0.113.0/24",
        as_path=[64512, 64500, 64501],
        origin_as=64512,
        next_hop="192.0.2.1",
        peer_ip="192.0.2.1",
        peer_as=64512,
        communities=["64512:100", "64512:200"],
        origin="IGP",
        is_hijack=False,
        scenario={"name": "test_hijack", "attack_step": "normal", "incident_id": "TEST-001"}
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    # Check required fields
    assert "event_type" in event
    assert event["event_type"] == "bmp.route_monitoring"

    assert "timestamp" in event
    assert isinstance(event["timestamp"], int)

    assert "source" in event
    assert event["source"]["feed"] == "bmp"
    assert event["source"]["observer"] == "bmp-collector-01"

    assert "attributes" in event
    attributes = event["attributes"]
    assert attributes["prefix"] == "203.0.113.0/24"
    assert attributes["as_path"] == [64512, 64500, 64501]
    assert attributes["origin_as"] == 64512
    assert attributes["next_hop"] == "192.0.2.1"
    assert attributes["peer_ip"] == "192.0.2.1"
    assert attributes["peer_as"] == 64512
    assert attributes["communities"] == ["64512:100", "64512:200"]
    assert attributes["origin"] == "IGP"
    assert attributes["is_hijack"] is False

    assert "scenario" in event
    assert event["scenario"]["name"] == "test_hijack"
    assert event["scenario"]["attack_step"] == "normal"
    assert event["scenario"]["incident_id"] == "TEST-001"


def test_bmp_route_monitoring_default_scenario():
    """Test emit_route_monitoring uses default scenario if not provided."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "test_scenario")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # Emit without scenario parameter
    generator.emit_route_monitoring(
        prefix="198.51.100.0/24",
        as_path=[64513, 64502],
        origin_as=64513,
        next_hop="192.0.2.2",
        peer_ip="192.0.2.2",
        peer_as=64513,
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    # Should use default scenario
    assert event["scenario"]["name"] == "test_scenario"
    assert event["scenario"]["attack_step"] is None
    assert event["scenario"]["incident_id"] is None


def test_bmp_hijack_event():
    """Test generating a hijack event."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "hijack_test")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # Emit hijack event
    generator.emit_route_monitoring(
        prefix="203.0.113.0/24",
        as_path=[65534, 64503],
        origin_as=65534,
        next_hop="192.0.2.3",
        peer_ip="192.0.2.3",
        peer_as=65534,
        communities=["65534:666"],
        origin="IGP",
        is_hijack=True,
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    assert event["attributes"]["is_hijack"] is True
    assert event["attributes"]["origin_as"] == 65534  # Attacker AS
    assert "65534:666" in event["attributes"]["communities"]


def test_bmp_peer_up_event():
    """Test emit_peer_up generates correct event."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "test_scenario")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    generator.emit_peer_up(
        peer_ip="192.0.2.1",
        peer_as=64512,
        peer_bgp_id="192.0.2.1",
        scenario={"name": "test_scenario", "attack_step": "peer_establish"}
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    assert event["event_type"] == "bmp.peer_up"
    assert event["attributes"]["peer_ip"] == "192.0.2.1"
    assert event["attributes"]["peer_as"] == 64512
    assert event["attributes"]["peer_bgp_id"] == "192.0.2.1"


def test_bmp_peer_down_event():
    """Test emit_peer_down generates correct event."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "test_scenario")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    generator.emit_peer_down(
        peer_ip="192.0.2.2",
        peer_as=64513,
        reason=2,
        scenario={"name": "test_scenario", "attack_step": "peer_drop"}
    )

    assert len(captured_events) == 1
    event = captured_events[0]

    assert event["event_type"] == "bmp.peer_down"
    assert event["attributes"]["peer_ip"] == "192.0.2.2"
    assert event["attributes"]["peer_as"] == 64513
    assert event["attributes"]["reason"] == 2


def test_multiple_bmp_events():
    """Test generating multiple BMP events with proper timestamps."""
    clock = SimulationClock()
    event_bus = EventBus()
    generator = BMPTelemetryGenerator(clock, event_bus, "multi_event_test")

    captured_events = []
    event_bus.subscribe(captured_events.append)

    # First event at time 0
    generator.emit_peer_up(
        peer_ip="192.0.2.1",
        peer_as=64512,
        peer_bgp_id="192.0.2.1"
    )

    # Advance time to 5 seconds
    clock.advance_to(5)

    # Second event at time 5
    generator.emit_route_monitoring(
        prefix="203.0.113.0/24",
        as_path=[64512, 64500],
        origin_as=64512,
        next_hop="192.0.2.1",
        peer_ip="192.0.2.1",
        peer_as=64512
    )

    # Advance time to 8 seconds
    clock.advance_to(8)

    # Third event at time 8
    generator.emit_peer_down(
        peer_ip="192.0.2.1",
        peer_as=64512,
        reason=1
    )

    assert len(captured_events) == 3

    # Check event types
    assert captured_events[0]["event_type"] == "bmp.peer_up"
    assert captured_events[1]["event_type"] == "bmp.route_monitoring"
    assert captured_events[2]["event_type"] == "bmp.peer_down"

    # Check timestamps are integers
    timestamps = [event["timestamp"] for event in captured_events]
    assert all(isinstance(ts, int) for ts in timestamps)

    # Check timestamps match clock advances
    assert timestamps[0] == 0  # First event at time 0
    assert timestamps[1] == 5  # Second event at time 5
    assert timestamps[2] == 8  # Third event at time 8
