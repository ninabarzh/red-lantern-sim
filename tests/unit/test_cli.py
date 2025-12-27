"""Unit tests for simulator.cli module.

These tests verify CLI orchestration behaviour, not engine internals.
"""

import sys

from unittest.mock import Mock, patch

import pytest

from simulator.cli import main


# ---------------------------------------------------------------------
# Argument and file handling
# ---------------------------------------------------------------------

def test_main_returns_1_when_scenario_not_found(capsys):
    result = main(["does_not_exist.yaml"])
    assert result == 1
    err = capsys.readouterr().err
    assert "Scenario file not found" in err


def test_main_requires_scenario_argument():
    with pytest.raises(SystemExit):
        main([])


# ---------------------------------------------------------------------
# Scenario loading
# ---------------------------------------------------------------------

def test_main_returns_2_when_scenario_load_fails(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    mock_scenario_runner.load.side_effect = Exception("Load failed")

    result = main([str(scenario)])
    assert result == 2
    err = capsys.readouterr().err
    assert "Failed to load scenario" in err
    mock_event_bus.subscribe.assert_called()


# ---------------------------------------------------------------------
# Telemetry loading
# ---------------------------------------------------------------------

def test_main_loads_telemetry_if_present(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    telemetry = tmp_path / "telemetry.py"
    telemetry.write_text(
        """
def register(event_bus, clock, scenario_name):
    event_bus.called = True
    event_bus.scenario_name = scenario_name
"""
    )

    result = main([str(scenario)])
    assert result == 0
    assert mock_event_bus.called
    assert mock_event_bus.scenario_name == "test_scenario"


def test_main_fails_when_telemetry_has_no_register(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    telemetry = tmp_path / "telemetry.py"
    telemetry.write_text("# no register here")

    result = main([str(scenario)])
    assert result == 2
    err = capsys.readouterr().err
    assert "does not define register()" in err


# ---------------------------------------------------------------------
# Event handling and adapter
# ---------------------------------------------------------------------

def test_handle_event_filters_scenario_lines_in_practice_mode(mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys):
    """Test that practice mode filters SCENARIO: lines."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    # Setup adapter to return both SCENARIO and normal lines
    def adapter_transform(event):
        if event.get("type") == "scenario_debug":
            return ["SCENARIO: Debug information", "Normal log line"]
        return ["Normal log line"]

    mock_adapter.transform.side_effect = adapter_transform

    # Store callback in a mutable container
    callback_store = []

    def mock_subscribe(callback):
        callback_store.append(callback)

    def mock_run():
        if callback_store:
            callback = callback_store[0]
            callback({"type": "scenario_debug", "message": "test"})
            callback({"type": "normal", "message": "test2"})

    mock_event_bus.subscribe.side_effect = mock_subscribe
    mock_scenario_runner.run.side_effect = mock_run

    result = main([str(scenario), "--mode", "practice"])
    assert result == 0

    captured = capsys.readouterr()
    # Should only have normal lines, not SCENARIO lines
    assert "Normal log line" in captured.out
    # Should appear twice (once from each event)
    assert captured.out.count("Normal log line") == 2
    # Should NOT have SCENARIO lines
    assert "SCENARIO: Debug information" not in captured.out


def test_handle_event_includes_scenario_lines_in_training_mode(mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys):
    """Test that training mode includes SCENARIO: lines."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    mock_adapter.transform.return_value = ["SCENARIO: Training debug line"]

    callback_store = []

    def mock_subscribe(callback):
        callback_store.append(callback)

    def mock_run():
        if callback_store:
            callback_store[0]({"type": "debug"})

    mock_event_bus.subscribe.side_effect = mock_subscribe
    mock_scenario_runner.run.side_effect = mock_run

    result = main([str(scenario), "--mode", "training"])
    assert result == 0

    captured = capsys.readouterr()
    assert "SCENARIO: Training debug line" in captured.out


# ---------------------------------------------------------------------
# JSON output mode
# ---------------------------------------------------------------------

def test_json_output_writes_to_file(mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path):
    """Test JSON mode writes events to file."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = ["Line 1", "Line 2"]

    callback_store = []

    def mock_subscribe(callback):
        callback_store.append(callback)

    def mock_run():
        if callback_store:
            callback = callback_store[0]
            callback({"type": "event1"})
            callback({"type": "event2"})

    mock_event_bus.subscribe.side_effect = mock_subscribe
    mock_scenario_runner.run.side_effect = mock_run

    result = main([str(scenario), "--output", "json", "--json-file", str(json_file)])
    assert result == 0
    assert json_file.exists()


# ---------------------------------------------------------------------
# Simulation execution
# ---------------------------------------------------------------------

def test_main_returns_3_when_simulation_fails(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    mock_scenario_runner.run.side_effect = Exception("Simulation boom")

    result = main([str(scenario)])
    assert result == 3
    err = capsys.readouterr().err
    assert "Simulation failed" in err
    mock_event_bus.subscribe.assert_called()


def test_main_runs_scenario_successfully(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    result = main([str(scenario)])
    assert result == 0
    mock_scenario_runner.load.assert_called_once()
    mock_scenario_runner.run.assert_called_once()
    mock_event_bus.subscribe.assert_called()


# ---------------------------------------------------------------------
# Background mode
# ---------------------------------------------------------------------

def test_main_runs_with_background_when_flag_set(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    # Create a simple mock for run_with_background
    mock_background_runner = Mock()

    with pytest.MonkeyPatch().context() as m:
        m.setattr("simulator.cli.run_with_background", mock_background_runner)

        result = main([str(scenario), "--background"])
        assert result == 0
        mock_event_bus.subscribe.assert_called()
        # Verify run_with_background was called
        assert mock_background_runner.called


def test_main_runs_scenario_directly_without_background_flag(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    result = main([str(scenario)])
    assert result == 0
    mock_scenario_runner.run.assert_called_once()


# ---------------------------------------------------------------------
# argv handling
# ---------------------------------------------------------------------

def test_main_uses_sys_argv_when_argv_is_none(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    original_argv = sys.argv
    try:
        sys.argv = ["simulator.cli", str(scenario)]
        result = main()
        assert result == 0
        mock_event_bus.subscribe.assert_called()
    finally:
        sys.argv = original_argv


"""Additional tests for missing coverage in simulator.cli module."""

# ---------------------------------------------------------------------
# Telemetry loading edge cases (line 89)
# ---------------------------------------------------------------------

def test_main_fails_when_telemetry_spec_is_none(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    """Test failure when importlib cannot create spec from telemetry file."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    # Create subdirectory structure
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    telemetry = subdir / "telemetry.py"
    telemetry.write_text("def register(event_bus, clock, scenario_name): pass")

    # Create scenario in parent dir so telemetry path is subdir/telemetry.py
    scenario = subdir / "scenario.yaml"
    scenario.write_text("id: test")

    # Patch to return None for this specific file
    original_spec_from_file = __import__('importlib.util', fromlist=['spec_from_file_location']).spec_from_file_location

    def mock_spec_from_file(name, location):
        # Only return None for our specific telemetry file
        if 'telemetry.py' in str(location):
            return None
        return original_spec_from_file(name, location)

    with patch("importlib.util.spec_from_file_location", side_effect=mock_spec_from_file):
        result = main([str(scenario)])
        assert result == 2
        captured = capsys.readouterr()
        assert "Could not load telemetry module" in captured.err


def test_main_fails_when_telemetry_spec_loader_is_none(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    """Test failure when spec.loader is None."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    telemetry = tmp_path / "telemetry.py"
    telemetry.write_text("def register(event_bus, clock, scenario_name): pass")

    # Create a real spec but with None loader
    original_spec_from_file = __import__('importlib.util', fromlist=['spec_from_file_location']).spec_from_file_location

    def mock_spec_from_file(name, location):
        if 'telemetry.py' in str(location):
            # Return a mock spec with None loader
            mock_spec = Mock()
            mock_spec.loader = None
            return mock_spec
        return original_spec_from_file(name, location)

    with patch("importlib.util.spec_from_file_location", side_effect=mock_spec_from_file):
        result = main([str(scenario)])
        assert result == 2
        captured = capsys.readouterr()
        assert "Could not load telemetry module" in captured.err


# ---------------------------------------------------------------------
# Background mode info message (line 127)
# ---------------------------------------------------------------------

def test_background_mode_prints_info_to_stderr(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    """Test that background mode prints configuration info to stderr in CLI mode."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    with patch("simulator.cli.run_with_background"):
        result = main([
            str(scenario),
            "--background",
            "--bgp-noise-rate", "1.5",
            "--cmdb-noise-rate", "0.3",
            "--output", "cli"
        ])

        assert result == 0
        err = capsys.readouterr().err
        assert "[INFO] Background noise enabled" in err
        assert "1.5 BGP updates/sec" in err
        assert "0.3 CMDB changes/sec" in err


def test_background_mode_no_info_in_json_output(mock_event_bus, mock_scenario_runner, tmp_path, capsys):
    """Test that background mode doesn't print info in JSON output mode."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    with patch("simulator.cli.run_with_background"):
        result = main([
            str(scenario),
            "--background",
            "--output", "json",
            "--json-file", str(json_file)
        ])

        assert result == 0
        err = capsys.readouterr().err
        # Info message should not appear in JSON mode
        assert "[INFO] Background noise enabled" not in err


# ---------------------------------------------------------------------
# JSON file write failure (lines 169-171)
# ---------------------------------------------------------------------

def test_main_returns_4_when_json_write_fails(mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys):
    """Test that JSON write failures are handled properly."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = ["Test line"]

    callback_store = []

    def mock_subscribe(callback):
        callback_store.append(callback)

    def mock_run():
        if callback_store:
            callback_store[0]({"type": "test"})

    mock_event_bus.subscribe.side_effect = mock_subscribe
    mock_scenario_runner.run.side_effect = mock_run

    # Mock Path.open() to raise an exception only for the JSON file
    original_open = tmp_path.__class__.open

    def selective_open(self, *args, **kwargs):
        if self == json_file:
            raise PermissionError("Cannot write")
        return original_open(self, *args, **kwargs)

    with patch.object(tmp_path.__class__, "open", selective_open):
        result = main([str(scenario), "--output", "json", "--json-file", str(json_file)])

        assert result == 4
        err = capsys.readouterr().err
        assert "Failed to write JSON file" in err


def test_main_handles_json_dump_failure(mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys):
    """Test handling of JSON serialization failures."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = ["Test line"]

    callback_store = []

    def mock_subscribe(callback):
        callback_store.append(callback)

    def mock_run():
        if callback_store:
            callback_store[0]({"type": "test"})

    mock_event_bus.subscribe.side_effect = mock_subscribe
    mock_scenario_runner.run.side_effect = mock_run

    # Mock json.dump to raise an exception
    with patch("json.dump", side_effect=TypeError("Object not serializable")):
        result = main([str(scenario), "--output", "json", "--json-file", str(json_file)])

        assert result == 4
        err = capsys.readouterr().err
        assert "Failed to write JSON file" in err
