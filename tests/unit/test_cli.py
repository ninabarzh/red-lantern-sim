"""
Unit tests for simulator.cli module.
"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from simulator.cli import (
    build_parser,
    load_scenario_telemetry,
    main,
    print_event,
)


class TestPrintEvent:
    """Tests for print_event function."""

    def test_print_event_outputs_to_stdout(self, capsys):
        """Test that print_event outputs the event dict to stdout."""
        event = {"type": "test", "data": "value"}
        print_event(event)
        captured = capsys.readouterr()
        assert str(event) in captured.out

    def test_print_event_handles_empty_dict(self, capsys):
        """Test print_event with empty dictionary."""
        event = {}
        print_event(event)
        captured = capsys.readouterr()
        assert "{}" in captured.out

    def test_print_event_handles_nested_structures(self, capsys):
        """Test print_event with nested data structures."""
        event = {
            "event_type": "bgp.update",
            "attributes": {
                "prefix": "203.0.113.0/24",
                "as_path": [65001, 65002]
            }
        }
        print_event(event)
        captured = capsys.readouterr()
        assert "bgp.update" in captured.out
        assert "prefix" in captured.out


class TestBuildParser:
    """Tests for build_parser function."""

    def test_parser_has_scenario_argument(self):
        """Test that parser includes required scenario argument."""
        parser = build_parser()
        # Check that 'scenario' is in the parser
        actions = {action.dest for action in parser._actions}
        assert "scenario" in actions

    def test_parser_scenario_type_is_path(self):
        """Test that scenario argument is typed as Path."""
        parser = build_parser()
        scenario_action = next(
            action for action in parser._actions if action.dest == "scenario"
        )
        assert scenario_action.type == Path

    def test_parser_parses_valid_scenario_path(self):
        """Test parsing with valid scenario path."""
        parser = build_parser()
        args = parser.parse_args(["scenario.yaml"])
        assert isinstance(args.scenario, Path)
        assert args.scenario == Path("scenario.yaml")

    def test_parser_description_present(self):
        """Test that parser has a description."""
        parser = build_parser()
        assert parser.description is not None
        assert "scenario" in parser.description.lower()


class TestLoadScenarioTelemetry:
    """Tests for load_scenario_telemetry function."""

    def test_no_telemetry_file_returns_silently(self, tmp_path):
        """Test that missing telemetry.py file doesn't raise error."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.touch()

        event_bus = Mock()
        clock = Mock()

        # Should not raise
        load_scenario_telemetry(scenario_path, event_bus, clock, "test_scenario")

    def test_telemetry_file_without_register_raises_error(self, tmp_path):
        """Test that telemetry.py without register() raises RuntimeError."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.touch()

        telemetry_path = tmp_path / "telemetry.py"
        telemetry_path.write_text("# Empty telemetry module\n")

        event_bus = Mock()
        clock = Mock()

        with pytest.raises(RuntimeError, match="does not define a register"):
            load_scenario_telemetry(scenario_path, event_bus, clock, "test_scenario")

    def test_telemetry_register_called_with_correct_args(self, tmp_path):
        """Test that register() is called with correct arguments."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.touch()

        telemetry_path = tmp_path / "telemetry.py"
        telemetry_path.write_text("""
def register(event_bus, clock, scenario_name):
    event_bus.test_called = True
    event_bus.test_scenario = scenario_name
""")

        event_bus = Mock()
        clock = Mock()
        scenario_id = "test_scenario"

        load_scenario_telemetry(scenario_path, event_bus, clock, scenario_id)

        assert event_bus.test_called is True
        assert event_bus.test_scenario == scenario_id

    def test_invalid_telemetry_module_raises_error(self, tmp_path):
        """Test that invalid Python in telemetry.py raises appropriate error."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.touch()

        telemetry_path = tmp_path / "telemetry.py"
        telemetry_path.write_text("this is not valid python syntax !!!")

        event_bus = Mock()
        clock = Mock()

        with pytest.raises(SyntaxError):
            load_scenario_telemetry(scenario_path, event_bus, clock, "test_scenario")

    def test_telemetry_with_spec_none_raises_error(self, tmp_path):
        """Test that spec loading failures are handled."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.touch()

        telemetry_path = tmp_path / "telemetry.py"
        telemetry_path.write_text("def register(event_bus, clock, scenario_name): pass")

        event_bus = Mock()
        clock = Mock()

        with patch("importlib.util.spec_from_file_location", return_value=None):
            with pytest.raises(RuntimeError, match="Could not load telemetry module"):
                load_scenario_telemetry(scenario_path, event_bus, clock, "test_scenario")


class TestMain:
    """Tests for main function."""

    def test_main_returns_1_when_scenario_not_found(self, capsys):
        """Test main returns 1 when scenario file doesn't exist."""
        result = main(["nonexistent_scenario.yaml"])
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.err

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_returns_2_when_scenario_load_fails(
        self, mock_event_bus, mock_runner, tmp_path, capsys
    ):
        """Test main returns 2 when scenario loading fails."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("invalid: yaml: content:")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.load.side_effect = Exception("Load failed")
        mock_runner.return_value = mock_runner_instance

        result = main([str(scenario_path)])
        assert result == 2

        captured = capsys.readouterr()
        assert "Failed to load scenario" in captured.err

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_returns_2_when_scenario_has_no_id(
        self, mock_event_bus, mock_runner, tmp_path, capsys
    ):
        """Test main returns 2 when scenario has no id field."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("name: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {}  # No id field
        mock_runner.return_value = mock_runner_instance

        result = main([str(scenario_path)])
        assert result == 2

        captured = capsys.readouterr()
        assert "no id field" in captured.err

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_returns_2_when_telemetry_load_fails(
        self, mock_event_bus, mock_runner, mock_load_telemetry, tmp_path, capsys
    ):
        """Test main returns 2 when telemetry loading fails."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        mock_load_telemetry.side_effect = Exception("Telemetry load failed")

        result = main([str(scenario_path)])
        assert result == 2

        captured = capsys.readouterr()
        assert "Failed to load scenario telemetry" in captured.err

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_returns_3_when_simulation_fails(
        self, mock_event_bus, mock_runner, _mock_load_telemetry, tmp_path, capsys
    ):
        """Test main returns 3 when simulation execution fails."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner_instance.run.side_effect = Exception("Simulation failed")
        mock_runner.return_value = mock_runner_instance

        result = main([str(scenario_path)])
        assert result == 3

        captured = capsys.readouterr()
        assert "Simulation failed" in captured.err

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_returns_0_on_success(
        self, mock_event_bus, mock_runner, _mock_load_telemetry, tmp_path
    ):
        """Test main returns 0 on successful execution."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        result = main([str(scenario_path)])
        assert result == 0

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_subscribes_print_event_to_event_bus(
        self, mock_event_bus, mock_runner, _mock_load_telemetry, tmp_path
    ):
        """Test that main subscribes print_event to the event bus."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        main([str(scenario_path)])

        # Check that subscribe was called with print_event
        mock_bus_instance.subscribe.assert_called()
        # Verify print_event was one of the subscribed handlers
        calls = mock_bus_instance.subscribe.call_args_list
        assert any(call[0][0].__name__ == "print_event" for call in calls)

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_calls_runner_methods_in_order(
        self, mock_event_bus, mock_runner, _mock_load_telemetry, tmp_path
    ):
        """Test that main calls runner.load() before runner.run()."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        main([str(scenario_path)])

        # Verify load() was called before run()
        mock_runner_instance.load.assert_called_once()
        mock_runner_instance.run.assert_called_once()

        # Check order: load should be called before run
        call_order = [call[0] for call in mock_runner_instance.method_calls]
        load_idx = call_order.index("load")
        run_idx = call_order.index("run")
        assert load_idx < run_idx

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_passes_scenario_id_to_telemetry_loader(
        self, mock_event_bus, mock_runner, mock_load_telemetry, tmp_path
    ):
        """Test that main passes correct scenario_id to load_scenario_telemetry."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        test_scenario_id = "my_test_scenario"
        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": test_scenario_id}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        main([str(scenario_path)])

        # Verify load_scenario_telemetry was called with correct scenario_id
        mock_load_telemetry.assert_called_once()
        call_kwargs = mock_load_telemetry.call_args[1]
        assert call_kwargs["scenario_id"] == test_scenario_id

    @patch("simulator.cli.load_scenario_telemetry")
    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_with_none_argv_uses_sys_argv(
        self, mock_event_bus, mock_runner, _mock_load_telemetry, tmp_path
    ):
        """Test that main() with no args uses sys.argv."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        # Temporarily modify sys.argv
        original_argv = sys.argv
        try:
            sys.argv = ["cli.py", str(scenario_path)]
            result = main()
            # Should execute without crashing
            assert result == 0
        finally:
            sys.argv = original_argv

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_creates_event_bus_instance(
        self, mock_event_bus, mock_runner, tmp_path
    ):
        """Test that main creates an EventBus instance."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        with patch("simulator.cli.load_scenario_telemetry"):
            main([str(scenario_path)])

        mock_event_bus.assert_called_once()

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_passes_event_bus_to_runner(
        self, mock_event_bus, mock_runner, tmp_path
    ):
        """Test that main passes EventBus to ScenarioRunner."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test_scenario"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        with patch("simulator.cli.load_scenario_telemetry"):
            main([str(scenario_path)])

        # Verify ScenarioRunner was instantiated with event_bus
        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args[1]
        assert "event_bus" in call_kwargs
        assert call_kwargs["event_bus"] == mock_bus_instance


class TestMainIntegration:
    """Integration-style tests for main function with real file system."""

    def test_main_with_complete_valid_scenario(self, tmp_path):
        """Integration test with a complete valid scenario setup."""
        # Create scenario file
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("""
id: integration_test
name: Integration Test Scenario
timeline:
  - timestamp: 0
    event: start
""")

        # Create telemetry file
        telemetry_path = tmp_path / "telemetry.py"
        telemetry_path.write_text("""
def register(event_bus, clock, scenario_name):
    # Simple registration that doesn't break
    pass
""")

        with patch("simulator.cli.ScenarioRunner") as mock_runner, \
             patch("simulator.cli.EventBus") as mock_event_bus:

            mock_bus_instance = Mock()
            mock_event_bus.return_value = mock_bus_instance

            mock_runner_instance = Mock()
            mock_runner_instance.scenario = {"id": "integration_test"}
            mock_runner_instance.clock = Mock()
            mock_runner.return_value = mock_runner_instance

            result = main([str(scenario_path)])

            assert result == 0
            mock_runner_instance.load.assert_called_once()
            mock_runner_instance.run.assert_called_once()

    def test_main_with_scenario_without_telemetry(self, tmp_path):
        """Test main works when telemetry.py doesn't exist."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("""
id: no_telemetry_test
name: No Telemetry Test
""")

        with patch("simulator.cli.ScenarioRunner") as mock_runner, \
             patch("simulator.cli.EventBus") as mock_event_bus:

            mock_bus_instance = Mock()
            mock_event_bus.return_value = mock_bus_instance

            mock_runner_instance = Mock()
            mock_runner_instance.scenario = {"id": "no_telemetry_test"}
            mock_runner_instance.clock = Mock()
            mock_runner.return_value = mock_runner_instance

            result = main([str(scenario_path)])

            assert result == 0


class TestEdgeCases:
    """Edge case tests for CLI module."""

    def test_print_event_with_none_values(self, capsys):
        """Test print_event handles None values in dict."""
        event = {"key": None, "nested": {"value": None}}
        print_event(event)
        captured = capsys.readouterr()
        assert "None" in captured.out

    def test_print_event_with_large_event(self, capsys):
        """Test print_event handles large events."""
        event = {f"key_{i}": f"value_{i}" for i in range(100)}
        print_event(event)
        captured = capsys.readouterr()
        assert "key_0" in captured.out
        assert "key_99" in captured.out

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_with_relative_path(
        self, mock_event_bus, mock_runner, tmp_path
    ):
        """Test main handles relative paths correctly."""
        scenario_path = tmp_path / "subdir" / "scenario.yaml"
        scenario_path.parent.mkdir(parents=True)
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": "test"}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        with patch("simulator.cli.load_scenario_telemetry"):
            main([str(scenario_path)])

        # Verify runner was called - we don't need the return value
        mock_runner_instance.run.assert_called_once()

    @patch("simulator.cli.ScenarioRunner")
    @patch("simulator.cli.EventBus")
    def test_main_with_scenario_id_containing_special_chars(
        self, mock_event_bus, mock_runner, tmp_path
    ):
        """Test main handles scenario IDs with special characters."""
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text("id: test")

        mock_bus_instance = Mock()
        mock_event_bus.return_value = mock_bus_instance

        special_id = "test-scenario_v1.2.3"
        mock_runner_instance = Mock()
        mock_runner_instance.scenario = {"id": special_id}
        mock_runner_instance.clock = Mock()
        mock_runner.return_value = mock_runner_instance

        with patch("simulator.cli.load_scenario_telemetry") as mock_load:
            main([str(scenario_path)])

            # Verify the special ID was passed correctly
            call_kwargs = mock_load.call_args[1]
            assert call_kwargs["scenario_id"] == special_id
            # Verify runner was called
            mock_runner_instance.run.assert_called_once()
