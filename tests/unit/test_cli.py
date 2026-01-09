"""
Unit tests for simulator.cli module.

These tests verify CLI orchestration behaviour, not engine internals.
"""

import json
from unittest.mock import mock_open

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


def test_main_returns_2_when_scenario_load_fails(
    mock_event_bus, mock_scenario_runner, tmp_path, capsys
):
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


def test_main_loads_telemetry_if_present(
    mock_event_bus, mock_scenario_runner, tmp_path
):
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


def test_main_fails_when_telemetry_has_no_register(
    mock_event_bus, mock_scenario_runner, tmp_path, capsys
):
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


def test_handle_event_filters_scenario_lines_in_practice_mode(
    mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys
):
    """Practice mode should filter SCENARIO: lines and strip scenario metadata."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    def adapter_transform(_event):
        return [
            "SCENARIO: Debug information",
            '{"event_type":"router.syslog","scenario":{"name":"test_scenario"}}',
            "Normal log line",
        ]

    mock_adapter.transform.side_effect = adapter_transform

    callbacks = []

    mock_event_bus.subscribe.side_effect = lambda cb: callbacks.append(cb)
    mock_scenario_runner.run.side_effect = lambda: [callbacks[0]({})]

    result = main([str(scenario), "--mode", "practice"])
    assert result == 0

    captured = capsys.readouterr().out
    assert "Normal log line" in captured
    assert "SCENARIO: Debug information" not in captured
    assert '"scenario"' not in captured


def test_handle_event_includes_scenario_lines_in_training_mode(
    mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, capsys
):
    """Training mode should include SCENARIO: lines and metadata."""
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    mock_adapter.transform.return_value = [
        '{"event_type":"router.syslog","scenario":{"name":"test_scenario"}}',
        "SCENARIO: Training debug line",
    ]

    callbacks = []
    mock_event_bus.subscribe.side_effect = lambda cb: callbacks.append(cb)
    mock_scenario_runner.run.side_effect = lambda: [callbacks[0]({})]

    result = main([str(scenario), "--mode", "training"])
    assert result == 0

    captured = capsys.readouterr().out
    assert "SCENARIO: Training debug line" in captured
    assert '"scenario":{"name":"test_scenario"}' in captured


# ---------------------------------------------------------------------
# JSON output mode
# ---------------------------------------------------------------------


def test_json_output_practice_mode_filters_metadata(
    mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path
):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = [
        '{"event_type":"router.syslog","scenario":{"name":"test_scenario"}}',
        "Normal log line",
    ]

    callbacks = []
    mock_event_bus.subscribe.side_effect = lambda cb: callbacks.append(cb)
    mock_scenario_runner.run.side_effect = lambda: [callbacks[0]({})]

    result = main(
        [
            str(scenario),
            "--output",
            "json",
            "--json-file",
            str(json_file),
            "--mode",
            "practice",
        ]
    )
    assert result == 0
    data = json.loads(json_file.read_text())
    for event_record in data:
        line = event_record["line"]
        if line.startswith("{"):
            parsed = json.loads(line)
            assert "scenario" not in parsed


def test_json_output_training_mode_includes_metadata(
    mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path
):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = [
        '{"event_type":"router.syslog","scenario":{"name":"test_scenario"}}'
    ]

    callbacks = []
    mock_event_bus.subscribe.side_effect = lambda cb: callbacks.append(cb)
    mock_scenario_runner.run.side_effect = lambda: [callbacks[0]({})]

    result = main(
        [
            str(scenario),
            "--output",
            "json",
            "--json-file",
            str(json_file),
            "--mode",
            "training",
        ]
    )
    assert result == 0
    data = json.loads(json_file.read_text())
    found = any('"scenario"' in ev["line"] for ev in data)
    assert found


def test_main_returns_4_on_json_write_failure(
    mock_event_bus, mock_scenario_runner, mock_adapter, tmp_path, monkeypatch
):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    json_file = tmp_path / "output.json"

    mock_adapter.transform.return_value = ["Test line"]
    callbacks = []
    mock_event_bus.subscribe.side_effect = lambda cb: callbacks.append(cb)
    mock_scenario_runner.run.side_effect = lambda: [callbacks[0]({})]

    # Patch Path.open to raise PermissionError for this test
    def fail_open(self, *args, **kwargs):
        if self == json_file:
            raise PermissionError("Cannot write")
        return self.__class__.open(self, *args, **kwargs)

    monkeypatch.setattr(json_file.__class__, "open", fail_open)

    result = main([str(scenario), "--output", "json", "--json-file", str(json_file)])
    assert result == 4


# ---------------------------------------------------------------------
# Simulation execution
# ---------------------------------------------------------------------


def test_main_returns_3_when_simulation_fails(
    mock_event_bus, mock_scenario_runner, tmp_path, capsys
):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    mock_scenario_runner.run.side_effect = Exception("Simulation boom")

    result = main([str(scenario)])
    assert result == 3
    err = capsys.readouterr().err
    assert "Simulation failed" in err
    mock_event_bus.subscribe.assert_called()


def test_main_runs_scenario_successfully(
    mock_event_bus, mock_scenario_runner, tmp_path
):
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


def test_main_runs_with_background_flag(mock_event_bus, mock_scenario_runner, tmp_path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")
    called = {}

    def fake_run_with_background(_runner, _feeds, _bus, _clock):
        called["yes"] = True

    import simulator.cli as cli

    original = cli.run_with_background
    cli.run_with_background = fake_run_with_background

    result = main([str(scenario), "--background"])
    assert result == 0
    assert called.get("yes")
    cli.run_with_background = original


def test_main_runs_scenario_directly_without_background_flag(
    mock_event_bus, mock_scenario_runner, tmp_path
):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("id: test")

    result = main([str(scenario)])
    assert result == 0
    mock_scenario_runner.run.assert_called_once()
