"""
Unit tests for telemetry/generators/bgp_updates.py
"""
from unittest.mock import Mock

import pytest

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.bgp_updates import BGPUpdateGenerator


class TestBGPUpdateGenerator:
    """Test suite for the BGPUpdateGenerator class."""

    def test_initialization(self):
        """Test that BGPUpdateGenerator initializes correctly."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)
        scenario_name = "test-scenario"

        generator = BGPUpdateGenerator(mock_clock, mock_bus, scenario_name)

        assert generator.clock is mock_clock
        assert generator.event_bus is mock_bus
        assert generator.scenario_name == scenario_name

    def test_emit_update_basic(self):
        """Test emitting a basic BGP UPDATE event."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 100

        mock_bus = Mock(spec=EventBus)
        scenario_name = "basic-update-test"

        generator = BGPUpdateGenerator(mock_clock, mock_bus, scenario_name)

        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530, 65531, 65532],
            origin_as=65530,
            next_hop="192.0.2.1"
        )

        # Verify event bus was called
        mock_bus.publish.assert_called_once()

        # Get the published event
        published_event = mock_bus.publish.call_args[0][0]

        # Verify event structure
        assert published_event["event_type"] == "bgp.update"
        assert published_event["timestamp"] == 100
        assert published_event["source"] == {"feed": "mock", "observer": "simulator"}

        # Verify attributes
        attributes = published_event["attributes"]
        assert attributes["prefix"] == "192.0.2.0/24"
        assert attributes["as_path"] == [65530, 65531, 65532]
        assert attributes["origin_as"] == 65530
        assert attributes["next_hop"] == "192.0.2.1"

        # Verify default scenario
        scenario = published_event["scenario"]
        assert scenario["name"] == scenario_name
        assert scenario["attack_step"] is None
        assert scenario["incident_id"] is None

    def test_emit_update_with_custom_scenario(self):
        """Test emitting UPDATE with custom scenario metadata."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 150

        mock_bus = Mock(spec=EventBus)
        scenario_name = "main-scenario"

        generator = BGPUpdateGenerator(mock_clock, mock_bus, scenario_name)

        custom_scenario = {
            "name": "custom-attack",
            "attack_step": "phase2",
            "incident_id": "inc-12345",
            "additional_field": "extra_data"
        }

        generator.emit_update(
            prefix="203.0.113.0/24",
            as_path=[64512],
            origin_as=64512,
            next_hop="203.0.113.1",
            scenario=custom_scenario
        )

        published_event = mock_bus.publish.call_args[0][0]

        # Custom scenario should override default
        assert published_event["scenario"] == custom_scenario
        # Other fields should still be correct
        assert published_event["timestamp"] == 150
        assert published_event["attributes"]["prefix"] == "203.0.113.0/24"

    def test_emit_update_empty_as_path(self):
        """Test emitting UPDATE with empty AS path."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "empty-path-test")

        generator.emit_update(
            prefix="198.51.100.0/24",
            as_path=[],  # Empty AS path
            origin_as=64496,
            next_hop="198.51.100.1"
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["attributes"]["as_path"] == []

    def test_emit_update_single_as_path(self):
        """Test emitting UPDATE with single AS in path."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "single-as-test")

        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530],  # Single AS
            origin_as=65530,
            next_hop="192.0.2.1"
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["attributes"]["as_path"] == [65530]
        assert published_event["attributes"]["origin_as"] == 65530

    def test_emit_withdraw_basic(self):
        """Test emitting a basic BGP WITHDRAW event."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 200

        mock_bus = Mock(spec=EventBus)
        scenario_name = "basic-withdraw-test"

        generator = BGPUpdateGenerator(mock_clock, mock_bus, scenario_name)

        generator.emit_withdraw(
            prefix="192.0.2.0/24",
            withdrawn_by_as=65530
        )

        mock_bus.publish.assert_called_once()
        published_event = mock_bus.publish.call_args[0][0]

        assert published_event["event_type"] == "bgp.withdraw"
        assert published_event["timestamp"] == 200
        assert published_event["source"] == {"feed": "mock", "observer": "simulator"}

        attributes = published_event["attributes"]
        assert attributes["prefix"] == "192.0.2.0/24"
        assert attributes["withdrawn_by_as"] == 65530

        scenario = published_event["scenario"]
        assert scenario["name"] == scenario_name
        assert scenario["attack_step"] is None
        assert scenario["incident_id"] is None

    def test_emit_withdraw_with_custom_scenario(self):
        """Test emitting WITHDRAW with custom scenario metadata."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "main-scenario")

        custom_scenario = {
            "name": "mitigation-phase",
            "attack_step": "cleanup",
            "incident_id": "inc-67890",
            "reason": "attack_mitigated"
        }

        generator.emit_withdraw(
            prefix="203.0.113.0/24",
            withdrawn_by_as=64512,
            scenario=custom_scenario
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["scenario"] == custom_scenario

    def test_emit_withdraw_zero_as(self):
        """Test emitting WITHDRAW with AS zero (edge case)."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "zero-as-test")

        generator.emit_withdraw(
            prefix="0.0.0.0/0",  # Default route
            withdrawn_by_as=0  # AS zero
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["attributes"]["withdrawn_by_as"] == 0

    def test_emit_withdraw_negative_as(self):
        """Test emitting WITHDRAW with negative AS (edge case)."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "negative-as-test")

        generator.emit_withdraw(
            prefix="192.0.2.0/24",
            withdrawn_by_as=-1  # Negative AS (unusual but testable)
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["attributes"]["withdrawn_by_as"] == -1

    def test_multiple_emissions(self):
        """Test emitting multiple events."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 300

        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "multi-event-test")

        # Emit UPDATE
        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530, 65531],
            origin_as=65530,
            next_hop="192.0.2.1"
        )

        # Emit WITHDRAW
        generator.emit_withdraw(
            prefix="192.0.2.0/24",
            withdrawn_by_as=65530
        )

        # Should be called twice
        assert mock_bus.publish.call_count == 2

        # Get both calls
        call_args = mock_bus.publish.call_args_list

        # First call should be UPDATE
        first_event = call_args[0][0][0]
        assert first_event["event_type"] == "bgp.update"

        # Second call should be WITHDRAW
        second_event = call_args[1][0][0]
        assert second_event["event_type"] == "bgp.withdraw"

    def test_timestamp_updates(self):
        """Test that different emissions use current clock time."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "timestamp-test")

        # First emission at time 100
        mock_clock.now.return_value = 100
        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530],
            origin_as=65530,
            next_hop="192.0.2.1"
        )

        # Second emission at time 200
        mock_clock.now.return_value = 200
        generator.emit_withdraw(
            prefix="192.0.2.0/24",
            withdrawn_by_as=65530
        )

        call_args = mock_bus.publish.call_args_list

        # Check timestamps
        assert call_args[0][0][0]["timestamp"] == 100
        assert call_args[1][0][0]["timestamp"] == 200

    def test_event_bus_error_propagation(self):
        """Test that EventBus exceptions are propagated."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        # Make publish raise an exception
        mock_bus.publish.side_effect = RuntimeError("EventBus failed")

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "error-test")

        # Should propagate the exception
        with pytest.raises(RuntimeError, match="EventBus failed"):
            generator.emit_update(
                prefix="192.0.2.0/24",
                as_path=[65530],
                origin_as=65530,
                next_hop="192.0.2.1"
            )

    def test_ipv6_prefix(self):
        """Test with IPv6 prefix."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "ipv6-test")

        generator.emit_update(
            prefix="2001:db8::/32",
            as_path=[65530, 65531],
            origin_as=65530,
            next_hop="2001:db8::1"
        )

        published_event = mock_bus.publish.call_args[0][0]
        assert published_event["attributes"]["prefix"] == "2001:db8::/32"
        assert published_event["attributes"]["next_hop"] == "2001:db8::1"

    def test_partial_scenario_override(self):
        """Test that custom scenario completely replaces default."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = BGPUpdateGenerator(mock_clock, mock_bus, "default-name")

        # Custom scenario with only some fields
        partial_scenario = {
            "name": "custom-name",
            "attack_step": "phase1"
            # incident_id is missing
        }

        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530],
            origin_as=65530,
            next_hop="192.0.2.1",
            scenario=partial_scenario
        )

        published_event = mock_bus.publish.call_args[0][0]

        # The entire custom scenario should be used
        assert published_event["scenario"] == partial_scenario
        # Should not have incident_id field since it wasn't in partial_scenario
        assert "incident_id" not in published_event["scenario"]

    def test_none_scenario_treated_as_none(self):
        """Test that explicitly passing None for scenario uses defaults."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        scenario_name = "explicit-none-test"
        generator = BGPUpdateGenerator(mock_clock, mock_bus, scenario_name)

        # Explicitly pass None
        generator.emit_update(
            prefix="192.0.2.0/24",
            as_path=[65530],
            origin_as=65530,
            next_hop="192.0.2.1",
            scenario=None  # Explicit None
        )

        published_event = mock_bus.publish.call_args[0][0]

        # Should use default scenario
        assert published_event["scenario"]["name"] == scenario_name
        assert published_event["scenario"]["attack_step"] is None
        assert published_event["scenario"]["incident_id"] is None


def test_module_imports():
    """Test that the module exports the expected names."""
    import telemetry.generators.bgp_updates as bgp_updates_module

    assert hasattr(bgp_updates_module, 'BGPUpdateGenerator')
    assert isinstance(bgp_updates_module.BGPUpdateGenerator, type)


def test_type_hints():
    """Test that type hints are present in the class."""
    import inspect

    generator_class = BGPUpdateGenerator

    # Check __init__ signature
    sig = inspect.signature(generator_class.__init__)
    params = list(sig.parameters.keys())
    assert "clock" in params
    assert "event_bus" in params
    assert "scenario_name" in params

    # Check emit_update signature
    sig = inspect.signature(generator_class.emit_update)
    assert "prefix" in sig.parameters
    assert "as_path" in sig.parameters
    assert "origin_as" in sig.parameters
    assert "next_hop" in sig.parameters
    assert "scenario" in sig.parameters

    # Check emit_withdraw signature
    sig = inspect.signature(generator_class.emit_withdraw)
    assert "prefix" in sig.parameters
    assert "withdrawn_by_as" in sig.parameters
    assert "scenario" in sig.parameters
