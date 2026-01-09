"""
Unit tests for telemetry/generators/latency_metrics.py
"""

from unittest.mock import Mock

import pytest

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from telemetry.generators.latency_metrics import LatencyMetricsGenerator


class TestLatencyMetricsGenerator:
    """Test suite for the LatencyMetricsGenerator class."""

    def test_initialization(self):
        """Test that LatencyMetricsGenerator initializes correctly."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)
        scenario_name = "latency-scenario"

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, scenario_name)

        assert generator.clock is mock_clock
        assert generator.event_bus is mock_bus
        assert generator.scenario_name == scenario_name

    def test_emit_basic(self):
        """Test emitting a basic latency metrics event."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 500

        mock_bus = Mock(spec=EventBus)
        scenario_name = "basic-latency-test"

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, scenario_name)

        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=45.2,
            jitter_ms=5.1,
            packet_loss_pct=0.05,
        )

        # Verify event bus was called
        mock_bus.publish.assert_called_once()

        # Get the published event
        published_event = mock_bus.publish.call_args[0][0]

        # Verify event structure
        assert published_event["event_type"] == "latency.metrics"
        assert published_event["timestamp"] == 500
        assert published_event["source"] == {"feed": "mock", "observer": "simulator"}

        # Verify attributes
        attributes = published_event["attributes"]
        assert attributes["source_router"] == "router-a"
        assert attributes["target_router"] == "router-b"
        assert attributes["latency_ms"] == 45.2
        assert attributes["jitter_ms"] == 5.1
        assert attributes["packet_loss_pct"] == 0.05

        # Verify default scenario
        scenario = published_event["scenario"]
        assert scenario["name"] == scenario_name
        assert scenario["attack_step"] is None
        assert scenario["incident_id"] is None

    def test_emit_with_custom_scenario(self):
        """Test emitting latency metrics with custom scenario metadata."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.return_value = 750

        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "main-scenario")

        custom_scenario = {
            "name": "network-congestion",
            "attack_step": "traffic-flood",
            "incident_id": "inc-33333",
            "severity": "high",
        }

        generator.emit(
            source_router="core-1",
            target_router="core-2",
            latency_ms=120.5,
            jitter_ms=15.3,
            packet_loss_pct=2.1,
            scenario=custom_scenario,
        )

        published_event = mock_bus.publish.call_args[0][0]

        # Custom scenario should override default
        assert published_event["scenario"] == custom_scenario
        # Other fields should still be correct
        assert published_event["timestamp"] == 750
        assert published_event["attributes"]["source_router"] == "core-1"
        assert published_event["attributes"]["latency_ms"] == 120.5

    def test_emit_zero_values(self):
        """Test emitting latency metrics with zero values."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "zero-values-test")

        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=0.0,  # Zero latency
            jitter_ms=0.0,  # Zero jitter
            packet_loss_pct=0.0,  # Zero packet loss
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["latency_ms"] == 0.0
        assert attributes["jitter_ms"] == 0.0
        assert attributes["packet_loss_pct"] == 0.0

    def test_emit_negative_values(self):
        """Test emitting latency metrics with negative values (edge case)."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(
            mock_clock, mock_bus, "negative-values-test"
        )

        # Negative values might indicate measurement errors or special cases
        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=-1.0,  # Negative latency (unusual)
            jitter_ms=2.0,
            packet_loss_pct=-0.5,  # Negative packet loss (invalid but testable)
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["latency_ms"] == -1.0
        assert attributes["packet_loss_pct"] == -0.5

    def test_emit_very_high_values(self):
        """Test emitting latency metrics with very high values."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "high-values-test")

        generator.emit(
            source_router="dc-east",
            target_router="dc-west",
            latency_ms=3500.75,  # Very high latency (3.5 seconds)
            jitter_ms=250.2,  # Very high jitter
            packet_loss_pct=25.8,  # Very high packet loss
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["latency_ms"] == 3500.75
        assert attributes["jitter_ms"] == 250.2
        assert attributes["packet_loss_pct"] == 25.8

    def test_emit_same_router(self):
        """Test emitting latency metrics with same source and target router."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "same-router-test")

        generator.emit(
            source_router="router-1",
            target_router="router-1",  # Same router
            latency_ms=0.5,
            jitter_ms=0.1,
            packet_loss_pct=0.0,
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["source_router"] == "router-1"
        assert attributes["target_router"] == "router-1"

    def test_emit_empty_router_names(self):
        """Test emitting latency metrics with empty router names."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "empty-names-test")

        generator.emit(
            source_router="",  # Empty source name
            target_router="",  # Empty target name
            latency_ms=10.0,
            jitter_ms=2.0,
            packet_loss_pct=1.0,
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["source_router"] == ""
        assert attributes["target_router"] == ""

    def test_emit_special_characters_in_names(self):
        """Test emitting latency metrics with special characters in router names."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "special-chars-test")

        generator.emit(
            source_router="router-a/interface-1",
            target_router="router-b:port-2",
            latency_ms=15.3,
            jitter_ms=3.2,
            packet_loss_pct=0.3,
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]
        assert attributes["source_router"] == "router-a/interface-1"
        assert attributes["target_router"] == "router-b:port-2"

    def test_emit_multiple_events(self):
        """Test emitting multiple latency metrics events."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.side_effect = [100, 200, 300]  # Different timestamps

        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "multi-event-test")

        # First emission
        generator.emit(
            source_router="router-1",
            target_router="router-2",
            latency_ms=10.0,
            jitter_ms=2.0,
            packet_loss_pct=0.1,
        )

        # Second emission
        generator.emit(
            source_router="router-2",
            target_router="router-3",
            latency_ms=15.0,
            jitter_ms=3.0,
            packet_loss_pct=0.2,
        )

        # Third emission
        generator.emit(
            source_router="router-3",
            target_router="router-1",
            latency_ms=8.0,
            jitter_ms=1.5,
            packet_loss_pct=0.05,
        )

        # Should be called three times
        assert mock_bus.publish.call_count == 3

        # Get all calls
        call_args = mock_bus.publish.call_args_list

        # Check timestamps
        assert call_args[0][0][0]["timestamp"] == 100
        assert call_args[1][0][0]["timestamp"] == 200
        assert call_args[2][0][0]["timestamp"] == 300

        # Check different router pairs
        assert call_args[0][0][0]["attributes"]["source_router"] == "router-1"
        assert call_args[1][0][0]["attributes"]["source_router"] == "router-2"
        assert call_args[2][0][0]["attributes"]["source_router"] == "router-3"

    def test_timestamp_updates(self):
        """Test that emissions use current clock time."""
        mock_clock = Mock(spec=SimulationClock)
        mock_clock.now.side_effect = [50, 150]  # Different times

        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "timestamp-test")

        # First emission
        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=10.0,
            jitter_ms=2.0,
            packet_loss_pct=0.1,
        )

        # Second emission
        generator.emit(
            source_router="router-b",
            target_router="router-c",
            latency_ms=20.0,
            jitter_ms=3.0,
            packet_loss_pct=0.2,
        )

        call_args = mock_bus.publish.call_args_list

        # Check timestamps are different
        assert call_args[0][0][0]["timestamp"] == 50
        assert call_args[1][0][0]["timestamp"] == 150

    def test_event_bus_error_propagation(self):
        """Test that EventBus exceptions are propagated."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        # Make publish raise an exception
        mock_bus.publish.side_effect = RuntimeError("EventBus failed")

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "error-test")

        # Should propagate the exception
        with pytest.raises(RuntimeError, match="EventBus failed"):
            generator.emit(
                source_router="router-a",
                target_router="router-b",
                latency_ms=10.0,
                jitter_ms=2.0,
                packet_loss_pct=0.1,
            )

    def test_partial_scenario_override(self):
        """Test that custom scenario completely replaces default."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "default-name")

        # Custom scenario with only some fields
        partial_scenario = {
            "name": "network-issue",
            "attack_step": "detected",
            # incident_id is missing
        }

        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=100.0,
            jitter_ms=20.0,
            packet_loss_pct=5.0,
            scenario=partial_scenario,
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
        generator = LatencyMetricsGenerator(mock_clock, mock_bus, scenario_name)

        # Explicitly pass None
        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=15.0,
            jitter_ms=3.0,
            packet_loss_pct=0.5,
            scenario=None,  # Explicit None
        )

        published_event = mock_bus.publish.call_args[0][0]

        # Should use default scenario
        assert published_event["scenario"]["name"] == scenario_name
        assert published_event["scenario"]["attack_step"] is None
        assert published_event["scenario"]["incident_id"] is None

    def test_float_precision(self):
        """Test that float values maintain precision."""
        mock_clock = Mock(spec=SimulationClock)
        mock_bus = Mock(spec=EventBus)

        generator = LatencyMetricsGenerator(mock_clock, mock_bus, "precision-test")

        generator.emit(
            source_router="router-a",
            target_router="router-b",
            latency_ms=12.3456789,  # Many decimal places
            jitter_ms=1.23456789,
            packet_loss_pct=0.123456789,
        )

        published_event = mock_bus.publish.call_args[0][0]
        attributes = published_event["attributes"]

        # Values should maintain their precision
        assert attributes["latency_ms"] == 12.3456789
        assert attributes["jitter_ms"] == 1.23456789
        assert attributes["packet_loss_pct"] == 0.123456789


def test_module_imports():
    """Test that the module exports the expected names."""
    import telemetry.generators.latency_metrics as latency_metrics_module

    assert hasattr(latency_metrics_module, "LatencyMetricsGenerator")
    assert isinstance(latency_metrics_module.LatencyMetricsGenerator, type)


def test_type_hints():
    """Test that type hints are present in the class."""
    import inspect

    generator_class = LatencyMetricsGenerator

    # Check __init__ signature
    sig = inspect.signature(generator_class.__init__)
    params = list(sig.parameters.keys())
    assert "clock" in params
    assert "event_bus" in params
    assert "scenario_name" in params

    # Check emit signature
    sig = inspect.signature(generator_class.emit)
    assert "source_router" in sig.parameters
    assert "target_router" in sig.parameters
    assert "latency_ms" in sig.parameters
    assert "jitter_ms" in sig.parameters
    assert "packet_loss_pct" in sig.parameters
    assert "scenario" in sig.parameters

    # Check parameter types
    params = sig.parameters
    assert params["latency_ms"].annotation is float
    assert params["jitter_ms"].annotation is float
    assert params["packet_loss_pct"].annotation is float


def test_edge_case_very_small_values():
    """Test with very small float values."""
    mock_clock = Mock(spec=SimulationClock)
    mock_bus = Mock(spec=EventBus)

    generator = LatencyMetricsGenerator(mock_clock, mock_bus, "small-values-test")

    generator.emit(
        source_router="router-a",
        target_router="router-b",
        latency_ms=0.0001,  # Very small latency
        jitter_ms=0.00001,  # Very small jitter
        packet_loss_pct=0.000001,  # Very small packet loss
    )

    published_event = mock_bus.publish.call_args[0][0]
    attributes = published_event["attributes"]
    assert attributes["latency_ms"] == 0.0001
    assert attributes["jitter_ms"] == 0.00001
    assert attributes["packet_loss_pct"] == 0.000001
