"""Test configuration and fixtures."""

import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def mock_event_bus(monkeypatch):
    """Mock EventBus for CLI tests."""
    mock_bus = Mock()
    monkeypatch.setattr("simulator.cli.EventBus", lambda: mock_bus)
    return mock_bus


@pytest.fixture
def mock_scenario_runner(monkeypatch):
    """Mock ScenarioRunner with default configuration."""
    mock_runner = Mock()
    mock_runner.scenario = {"id": "test_scenario"}
    mock_runner.clock = Mock()
    monkeypatch.setattr(
        "simulator.cli.ScenarioRunner", lambda scenario_path, event_bus: mock_runner
    )
    return mock_runner


@pytest.fixture
def mock_adapter(monkeypatch):
    """Mock ScenarioAdapter."""
    mock_adapter = Mock()
    monkeypatch.setattr("simulator.cli.ScenarioAdapter", lambda: mock_adapter)
    return mock_adapter


@pytest.fixture
def mock_clock() -> Mock:
    """Mock simulation clock."""
    clock = Mock()
    clock.current_time.return_value = 1700000000
    clock.now.return_value = datetime.now(UTC)  # Timezone-aware
    return clock


@pytest.fixture
def current_utc_time() -> datetime:
    """Provide current UTC time for tests."""
    return datetime.now(UTC)


@pytest.fixture
def sample_bgp_update() -> dict[str, object]:
    """Sample BGP update for testing."""
    return {
        "timestamp": 1700000000,
        "prefix": "203.0.113.0/24",
        "as_path": [6939, 174, 64500],
        "origin_as": 64500,
        "next_hop": "198.32.176.1",
    }


@pytest.fixture
def european_environment():
    """Set up European environment variables."""
    import os

    original_collector = os.getenv("ROUTEVIEWS_COLLECTOR")
    original_peer_ip = os.getenv("ROUTEVIEWS_PEER_IP")

    # Set European defaults
    os.environ["ROUTEVIEWS_COLLECTOR"] = "route-views.amsix"
    os.environ["ROUTEVIEWS_PEER_IP"] = "193.0.0.56"

    yield

    # Restore original environment
    if original_collector:
        os.environ["ROUTEVIEWS_COLLECTOR"] = original_collector
    else:
        os.environ.pop("ROUTEVIEWS_COLLECTOR", None)

    if original_peer_ip:
        os.environ["ROUTEVIEWS_PEER_IP"] = original_peer_ip
    else:
        os.environ.pop("ROUTEVIEWS_PEER_IP", None)
