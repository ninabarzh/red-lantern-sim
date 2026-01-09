"""Unit tests for simulator.engine.simulation_engine module."""

from unittest.mock import Mock, call

import pytest

from simulator.engine.simulation_engine import BackgroundFeed, run_with_background

# ---------------------------------------------------------------------
# Test BackgroundFeed base class
# ---------------------------------------------------------------------


def test_background_feed_is_abstract():
    """Test that BackgroundFeed is an abstract base class."""
    feed = BackgroundFeed()

    with pytest.raises(NotImplementedError):
        feed.generate_events(duration=100)


class TestBackgroundFeed:
    """Tests for BackgroundFeed base class functionality."""

    def test_background_feed_instantiation(self):
        """Test that BackgroundFeed can be instantiated."""
        feed = BackgroundFeed()
        assert isinstance(feed, BackgroundFeed)


# ---------------------------------------------------------------------
# Test run_with_background function
# ---------------------------------------------------------------------


def test_run_with_background_with_empty_scenario(mock_event_bus, mock_clock):
    """Test run_with_background with empty scenario timeline."""
    # Mock scenario runner with empty timeline
    mock_runner = Mock()
    mock_runner.scenario = {"id": "test_scenario", "timeline": []}

    # Mock background feed
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = []

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Verify feed was called with default duration
    mock_feed.generate_events.assert_called_once_with(3600)  # default duration
    # No events to publish
    mock_event_bus.publish.assert_not_called()


def test_run_with_background_with_scenario_events(mock_event_bus, mock_clock):
    """Test run_with_background with scenario events only."""
    # Mock scenario runner with timeline
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [
            {"t": 10, "event": "start"},
            {"t": 30, "event": "attack"},
            {"t": 50, "event": "end"},
        ],
    }

    # Mock background feed with no events
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = []

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Verify feed was called with correct duration (max timestamp = 50)
    mock_feed.generate_events.assert_called_once_with(50)

    # Verify events were published in order
    assert mock_event_bus.publish.call_count == 3

    # Check that clock was advanced for each event
    assert mock_clock.advance_to.call_count == 3
    mock_clock.advance_to.assert_has_calls(
        [call(10), call(30), call(50)], any_order=False
    )


def test_run_with_background_with_background_events(mock_event_bus, mock_clock):
    """Test run_with_background with background events only."""
    # Mock scenario runner with no timeline
    mock_runner = Mock()
    mock_runner.scenario = {"id": "test_scenario", "timeline": []}

    # Mock background feed with events
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = [
        (15, {"type": "bgp_update", "prefix": "192.0.2.0/24"}),
        (45, {"type": "config_change", "device": "router01"}),
    ]

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Verify feed was called
    mock_feed.generate_events.assert_called_once_with(3600)

    # Verify events were published
    assert mock_event_bus.publish.call_count == 2

    # Check clock advancement
    mock_clock.advance_to.assert_has_calls([call(15), call(45)])


def test_run_with_background_mixed_events_sorted(mock_event_bus, mock_clock):
    """Test that scenario and background events are sorted by timestamp."""
    # Mock scenario runner
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [
            {"t": 20, "event": "scenario_event_1"},
            {"t": 40, "event": "scenario_event_2"},
        ],
    }

    # Mock background feed with events at different timestamps
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = [
        (10, {"type": "bgp_update", "prefix": "192.0.2.0/24"}),
        (30, {"type": "bgp_update", "prefix": "198.51.100.0/24"}),
        (50, {"type": "bgp_update", "prefix": "203.0.113.0/24"}),
    ]

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Verify events published in correct order
    assert mock_event_bus.publish.call_count == 5

    # Check order: background(10), scenario(20), background(30), scenario(40), background(50)
    mock_clock.advance_to.assert_has_calls(
        [call(10), call(20), call(30), call(40), call(50)], any_order=False
    )


def test_run_with_background_multiple_feeds(mock_event_bus, mock_clock):
    """Test run_with_background with multiple background feeds."""
    # Mock scenario runner
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [{"t": 25, "event": "scenario_event"}],
    }

    # Mock multiple background feeds
    mock_feed1 = Mock(spec=BackgroundFeed)
    mock_feed1.generate_events.return_value = [
        (10, {"source": "feed1", "event": "event1"}),
        (20, {"source": "feed1", "event": "event2"}),
    ]

    mock_feed2 = Mock(spec=BackgroundFeed)
    mock_feed2.generate_events.return_value = [
        (15, {"source": "feed2", "event": "event3"}),
        (30, {"source": "feed2", "event": "event4"}),
    ]

    run_with_background(
        mock_runner, [mock_feed1, mock_feed2], mock_event_bus, mock_clock
    )

    # Verify both feeds were called
    mock_feed1.generate_events.assert_called_once_with(25)  # max timestamp
    mock_feed2.generate_events.assert_called_once_with(25)

    # Verify all events published (1 scenario + 2 + 2 = 5 total)
    assert mock_event_bus.publish.call_count == 5

    # Verify order: feed1(10), feed2(15), feed1(20), scenario(25), feed2(30)
    mock_clock.advance_to.assert_has_calls(
        [call(10), call(15), call(20), call(25), call(30)]
    )


def test_run_with_background_events_with_missing_timestamp(mock_event_bus, mock_clock):
    """Test handling of scenario events without explicit timestamp."""
    # Mock scenario runner with events missing 't' key
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [
            {"event": "start"},  # No timestamp, should default to 0
            {"t": 30, "event": "middle"},
            {"event": "end"},  # No timestamp, should default to 0
        ],
    }

    # Mock background feed
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = []

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Verify duration calculation uses max of explicit timestamps (30)
    mock_feed.generate_events.assert_called_once_with(30)

    # Verify events published (all 3)
    assert mock_event_bus.publish.call_count == 3

    # Check that events with missing 't' get timestamp 0
    mock_clock.advance_to.assert_has_calls([call(0), call(0), call(30)])


def test_run_with_background_duplicate_timestamps(mock_event_bus, mock_clock):
    """Test handling of events with duplicate timestamps."""
    # Mock scenario runner
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [
            {"t": 10, "event": "scenario1"},
            {"t": 10, "event": "scenario2"},  # Same timestamp
        ],
    }

    # Mock background feed with same timestamp
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = [
        (10, {"type": "background"})  # Same timestamp
    ]

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # All 3 events should be published
    assert mock_event_bus.publish.call_count == 3

    # Clock should advance to 10 THREE times (once for each event at time 10)
    # NOT assert_called_once_with(10) - that would fail. It did.
    assert mock_clock.advance_to.call_count == 3

    # All calls should be with timestamp 10
    mock_clock.advance_to.assert_has_calls([call(10), call(10), call(10)])


def test_run_with_background_negative_timestamps(mock_event_bus, mock_clock):
    """Test handling of negative timestamps."""
    # Mock scenario runner with negative timestamp
    mock_runner = Mock()
    mock_runner.scenario = {
        "id": "test_scenario",
        "timeline": [
            {"t": -5, "event": "negative_time"},
            {"t": 10, "event": "positive_time"},
        ],
    }

    # Mock background feed
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = []

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Both events should be published
    assert mock_event_bus.publish.call_count == 2

    # Clock should advance to negative time
    mock_clock.advance_to.assert_has_calls([call(-5), call(10)])


def test_run_with_background_no_scenario_id(mock_event_bus, mock_clock):
    """Test run_with_background when scenario has no ID."""
    # Mock scenario runner without ID
    mock_runner = Mock()
    mock_runner.scenario = {"timeline": [{"t": 10, "event": "test"}]}  # No 'id' field

    # Mock background feed
    mock_feed = Mock(spec=BackgroundFeed)
    mock_feed.generate_events.return_value = []

    run_with_background(mock_runner, [mock_feed], mock_event_bus, mock_clock)

    # Should still work
    assert mock_event_bus.publish.call_count == 1
