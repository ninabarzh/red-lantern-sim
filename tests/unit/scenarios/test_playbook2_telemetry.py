import yaml
from pathlib import Path
from unittest.mock import Mock

from simulator.scenarios.medium.playbook2 import telemetry


SCENARIO_PATH = Path(
    "simulator/scenarios/medium/playbook2/scenario.yaml"
)


def load_scenario():
    return yaml.safe_load(SCENARIO_PATH.read_text())


def make_runner_event(scenario_id: str, t: int, entry: dict) -> dict:
    return {
        "timestamp": t,
        "scenario_id": scenario_id,
        "entry": entry,
    }


def test_playbook2_telemetry_mappings(mock_clock):
    scenario = load_scenario()

    bus = Mock()
    published = []
    subscribers = []

    bus.publish.side_effect = lambda evt: published.append(evt)
    bus.subscribe.side_effect = lambda handler: subscribers.append(handler)

    telemetry.register(bus, mock_clock, "playbook2")

    assert subscribers

    for item in scenario["timeline"]:
        event = make_runner_event("playbook2", item["t"], item)
        for handler in subscribers:
            handler(event)

    assert published

    for evt in published:
        assert "timestamp" in evt
        assert "event_type" in evt or "type" in evt
