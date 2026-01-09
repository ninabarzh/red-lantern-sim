"""
Unit tests for simulator/engine/scenario_runner.py
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest
import yaml

from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner


class TestScenarioRunner:
    """Test suite for the ScenarioRunner class."""

    def test_initialization(self):
        """Test that ScenarioRunner initializes correctly."""
        mock_path = Path("/test/scenario.yaml")
        mock_bus = Mock(spec=EventBus)

        runner = ScenarioRunner(mock_path, mock_bus)

        assert runner.scenario_path == mock_path
        assert runner.event_bus is mock_bus
        assert isinstance(runner.clock, SimulationClock)
        assert runner.scenario == {}

    def test_load_valid_scenario(self):
        """Test loading a valid scenario YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "test-scenario"
            timeline:
              - t: 10
                type: "bgp_announce"
                prefix: "192.0.2.0/24"
              - t: 20
                type: "bgp_withdraw"
                prefix: "192.0.2.0/24"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()

            assert runner.scenario["id"] == "test-scenario"
            assert len(runner.scenario["timeline"]) == 2
            assert runner.scenario["timeline"][0]["t"] == 10
            assert runner.scenario["timeline"][0]["type"] == "bgp_announce"
            assert runner.scenario["timeline"][1]["t"] == 20
            assert runner.scenario["timeline"][1]["type"] == "bgp_withdraw"
        finally:
            temp_path.unlink()

    def test_load_missing_file(self):
        """Test loading a non-existent scenario file."""
        mock_path = Path("/non/existent/scenario.yaml")
        mock_bus = Mock(spec=EventBus)
        runner = ScenarioRunner(mock_path, mock_bus)

        with pytest.raises(FileNotFoundError):
            runner.load()

    def test_load_invalid_yaml(self):
        """Test loading invalid YAML content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: [content")
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)

            with pytest.raises(yaml.YAMLError):
                runner.load()
        finally:
            temp_path.unlink()

    def test_load_scenario_not_dict(self):
        """Test loading a scenario that's not a dictionary."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("- item1\n- item2\n- item3")
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)

            with pytest.raises(ValueError) as exc_info:
                runner.load()

            assert "Scenario file must be a YAML mapping (dict)" in str(exc_info.value)
        finally:
            temp_path.unlink()

    def test_load_missing_timeline(self):
        """Test loading a scenario without a timeline section."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "no-timeline"
            description: "This scenario has no timeline"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)

            with pytest.raises(ValueError) as exc_info:
                runner.load()

            assert "Scenario is missing a 'timeline' section" in str(exc_info.value)
        finally:
            temp_path.unlink()

    def test_load_timeline_not_list(self):
        """Test loading a scenario where timeline is not a list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "bad-timeline"
            timeline:
              t: 10
              type: "event"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)

            with pytest.raises(ValueError) as exc_info:
                runner.load()

            assert "'timeline' must be a list of events" in str(exc_info.value)
        finally:
            temp_path.unlink()

    def test_run_empty_timeline(self):
        """Test running a scenario with an empty timeline."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "empty-timeline"
            timeline: []
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run()

            # Clock should remain at 0
            assert runner.clock.now() == 0
            # No events should be published
            mock_bus.publish.assert_not_called()
            # EventBus should not be closed
            mock_bus.close.assert_not_called()
        finally:
            temp_path.unlink()

    def test_run_sorted_timeline(self):
        """Test that timeline events are sorted by time."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "unsorted-timeline"
            timeline:
              - t: 30
                type: "event_c"
              - t: 10
                type: "event_a"
              - t: 20
                type: "event_b"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()

            # Track calls to publish
            published_events = []

            def capture_event(event):
                published_events.append(event)

            mock_bus.publish.side_effect = capture_event

            runner.run()

            # Verify events were published in time order
            assert len(published_events) == 3
            assert published_events[0]["entry"]["type"] == "event_a"
            assert published_events[0]["timestamp"] == 10
            assert published_events[1]["entry"]["type"] == "event_b"
            assert published_events[1]["timestamp"] == 20
            assert published_events[2]["entry"]["type"] == "event_c"
            assert published_events[2]["timestamp"] == 30

            # Verify clock advanced to last time
            assert runner.clock.now() == 30
        finally:
            temp_path.unlink()

    def test_run_events_without_time(self):
        """Test running events that don't have an explicit 't' field."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "no-time-events"
            timeline:
              - type: "event1"
              - t: 5
                type: "event2"
              - type: "event3"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()

            published_events = []

            def capture_event(event):
                published_events.append(event)

            mock_bus.publish.side_effect = capture_event

            runner.run()

            # Events without 't' should default to 0 and come first
            assert len(published_events) == 3
            assert published_events[0]["entry"]["type"] == "event1"
            assert published_events[0]["timestamp"] == 0
            assert (
                published_events[1]["entry"]["type"] == "event3"
            )  # Second event without 't'
            assert published_events[1]["timestamp"] == 0
            assert published_events[2]["entry"]["type"] == "event2"
            assert published_events[2]["timestamp"] == 5
        finally:
            temp_path.unlink()

    def test_run_close_bus_true(self):
        """Test running with close_bus=True."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "close-bus-test"
            timeline:
              - t: 1
                type: "test_event"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run(close_bus=True)

            # EventBus should be closed
            mock_bus.close.assert_called_once()
        finally:
            temp_path.unlink()

    def test_run_close_bus_false(self):
        """Test running with close_bus=False (default)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "dont-close-bus-test"
            timeline:
              - t: 1
                type: "test_event"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run(close_bus=False)  # Explicitly false
            runner.run()  # Default should also be false

            # EventBus should NOT be closed
            mock_bus.close.assert_not_called()
        finally:
            temp_path.unlink()

    def test_run_event_structure(self):
        """Test that published events have the correct structure."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "event-structure-test"
            timeline:
              - t: 42
                type: "custom_event"
                data: "test data"
                extra: "field"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()

            published_events = []

            def capture_event(event):
                published_events.append(event)

            mock_bus.publish.side_effect = capture_event

            runner.run()

            assert len(published_events) == 1
            event = published_events[0]

            # Check the event structure
            assert event["timestamp"] == 42
            assert event["scenario_id"] == "event-structure-test"
            assert "entry" in event
            assert event["entry"]["t"] == 42
            assert event["entry"]["type"] == "custom_event"
            assert event["entry"]["data"] == "test data"
            assert event["entry"]["extra"] == "field"
        finally:
            temp_path.unlink()

    def test_reset(self):
        """Test resetting the scenario runner."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "reset-test"
            timeline:
              - t: 100
                type: "event"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run()

            # Clock should be at 100 after running
            assert runner.clock.now() == 100

            # Reset should set clock back to 0
            runner.reset()
            assert runner.clock.now() == 0

            # Scenario data should still be loaded
            assert runner.scenario["id"] == "reset-test"
        finally:
            temp_path.unlink()

    def test_reset_doesnt_clear_event_bus(self):
        """Test that reset doesn't clear the event bus."""
        mock_bus = Mock(spec=EventBus)
        mock_path = Path("/test/scenario.yaml")
        runner = ScenarioRunner(mock_path, mock_bus)

        runner.reset()

        # Should not interact with event bus
        mock_bus.close.assert_not_called()
        # No method to "clear" subscribers, but if there were, it shouldn't be called

    @patch("simulator.engine.scenario_runner.SimulationClock")
    def test_clock_advance_to_called(self, mock_clock_class):
        """Test that clock.advance_to is called with correct times."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "clock-test"
            timeline:
              - t: 10
                type: "event1"
              - t: 20
                type: "event2"
              - t: 20  # Same time as previous
                type: "event3"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_clock = Mock()
            mock_clock.now.return_value = 0
            mock_clock_class.return_value = mock_clock

            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run()

            # Clock should advance to each event time (3 calls total)
            # The ScenarioRunner calls advance_to for every event, even at same time
            expected_calls = [call(10), call(20), call(20)]
            mock_clock.advance_to.assert_has_calls(expected_calls)
            assert mock_clock.advance_to.call_count == 3  # Fixed: 3 calls, not 2
        finally:
            temp_path.unlink()

    @patch("simulator.engine.scenario_runner.SimulationClock")
    def test_clock_now_called_for_timestamp(self, mock_clock_class):
        """Test that clock.now() is called for each event timestamp."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "clock-now-test"
            timeline:
              - t: 10
                type: "event1"
              - t: 20
                type: "event2"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            mock_clock = Mock()
            mock_clock.now.return_value = 0
            mock_clock_class.return_value = mock_clock

            mock_bus = Mock(spec=EventBus)
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run()

            # clock.now() should be called after each advance_to to get timestamp
            # This happens in the run() method: timestamp = self.clock.now()
            assert mock_clock.now.call_count >= 2  # At least 2 times, maybe more
        finally:
            temp_path.unlink()


class TestScenarioRunnerIntegration:
    """Integration tests for ScenarioRunner."""

    def test_end_to_end_with_real_clock_and_bus(self):
        """Test a complete scenario run with real Clock and EventBus."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "integration-test"
            timeline:
              - t: 5
                type: "start"
              - t: 15
                type: "middle"
              - t: 25
                type: "end"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            # Use real EventBus to test integration
            from simulator.engine.event_bus import EventBus as RealEventBus

            event_bus = RealEventBus()

            received_events = []

            def event_handler(event):
                received_events.append(event)

            event_bus.subscribe(event_handler)

            runner = ScenarioRunner(temp_path, event_bus)
            runner.load()
            runner.run()

            # Verify events were received
            assert len(received_events) == 3
            assert received_events[0]["timestamp"] == 5
            assert received_events[0]["entry"]["type"] == "start"
            assert received_events[1]["timestamp"] == 15
            assert received_events[1]["entry"]["type"] == "middle"
            assert received_events[2]["timestamp"] == 25
            assert received_events[2]["entry"]["type"] == "end"

            # EventBus should NOT be closed by default
            # (Can't easily test this without exposing internal state)
        finally:
            temp_path.unlink()


def test_scenario_runner_module_imports():
    """Test that the module exports the expected names."""
    import simulator.engine.scenario_runner as scenario_runner_module

    assert hasattr(scenario_runner_module, "ScenarioRunner")
    assert isinstance(scenario_runner_module.ScenarioRunner, type)


# Test file encoding handling
def test_load_with_utf8_encoding():
    """Test loading a scenario file with UTF-8 encoding."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        # Include some UTF-8 characters
        scenario_content = """
        id: "utf8-test"
        description: "Test with UTF-8: café résumé"
        timeline:
          - t: 1
            type: "test"
            message: "café"
        """
        f.write(scenario_content)
        temp_path = Path(f.name)

    try:
        mock_bus = Mock(spec=EventBus)
        runner = ScenarioRunner(temp_path, mock_bus)

        # Should not raise UnicodeDecodeError
        runner.load()

        assert runner.scenario["id"] == "utf8-test"
        assert "café" in runner.scenario["description"]
    finally:
        temp_path.unlink()


def test_advance_to_same_time_multiple_times():
    """Test that advance_to() is called even for events at same time."""
    # This test verifies the actual behavior observed in the failure
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        scenario_content = """
        id: "same-time-test"
        timeline:
          - t: 10
            type: "event1"
          - t: 10
            type: "event2"
          - t: 10
            type: "event3"
        """
        f.write(scenario_content)
        temp_path = Path(f.name)

    try:
        mock_bus = Mock(spec=EventBus)

        # Track advance_to calls
        advance_calls = []
        original_advance_to = SimulationClock.advance_to

        def track_advance_to(self, target_time):
            advance_calls.append(target_time)
            return original_advance_to(self, target_time)

        with patch.object(SimulationClock, "advance_to", track_advance_to):
            runner = ScenarioRunner(temp_path, mock_bus)
            runner.load()
            runner.run()

            # Should be called 3 times, all with time 10
            assert len(advance_calls) == 3
            assert all(t == 10 for t in advance_calls)
    finally:
        temp_path.unlink()
