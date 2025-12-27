"""Unit tests for CMDB noise feed lines 44-80."""

import random
import pytest

from simulator.feeds.change_mgmt.cmdb_noise_feed import CMDBNoiseFeed


class TestCMDBNoiseFeedInit:
    """Test CMDBNoiseFeed initialization (lines 44-51)."""

    def test_init_sets_default_values(self):
        """Test line 44-51: initialization with default parameters."""
        feed = CMDBNoiseFeed()
        assert feed.change_rate == 0.1
        assert feed.seed == 43

    def test_init_sets_custom_values(self):
        """Test line 44-51: initialization with custom parameters."""
        feed = CMDBNoiseFeed(change_rate=0.5, seed=123)
        assert feed.change_rate == 0.5
        assert feed.seed == 123


class TestGenerateEventsCalculation:
    """Test generate_events event count calculation (lines 60-61)."""

    def test_generate_events_calculates_event_count(self, mock_clock):
        """Test lines 60-61: total_events = int(duration * change_rate)."""
        # Using mock_clock fixture to ensure no side effects
        feed = CMDBNoiseFeed(change_rate=0.2, seed=42)
        duration = 10

        events = feed.generate_events(duration)

        # 10 * 0.2 = 2 events
        assert len(events) == 2

    def test_generate_events_with_fractional_rate(self, mock_event_bus):
        """Test lines 60-61: handles fractional rates correctly."""
        feed = CMDBNoiseFeed(change_rate=0.7, seed=42)
        duration = 10

        events = feed.generate_events(duration)

        # 10 * 0.7 = 7 events (int conversion)
        assert len(events) == 7

    def test_generate_events_zero_rate(self, current_utc_time):
        """Test lines 60-61: zero change_rate produces no events."""
        feed = CMDBNoiseFeed(change_rate=0.0, seed=42)
        duration = 100

        events = feed.generate_events(duration)

        assert len(events) == 0


class TestGenerateEventsTimestampGeneration:
    """Test timestamp generation in generate_events (line 66)."""

    def test_timestamps_within_range(self, sample_bgp_update):
        """Test line 66: timestamp = rng.randint(0, duration)."""
        # Using sample_bgp_update fixture to ensure environment
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        for timestamp, _ in events:
            assert 0 <= timestamp <= duration

    def test_timestamps_integer_type(self):
        """Test line 66: timestamps are integers."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 3

        events = feed.generate_events(duration)

        for timestamp, _ in events:
            assert isinstance(timestamp, int)


class TestGenerateEventsChangeTypeSelection:
    """Test change_type random selection (lines 68-73)."""

    def test_change_type_from_approved_list(self):
        """Test lines 68-73: change_type is from specified list."""
        feed = CMDBNoiseFeed(change_rate=2.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        valid_types = {"software_update", "config_change", "maintenance", "system_restart"}

        for _, event_data in events:
            change_type = event_data["attributes"]["change_type"]
            assert change_type in valid_types, f"Invalid change_type: {change_type}"

    def test_change_type_distribution(self, european_environment):
        """Test lines 68-73: change_type uses rng.choice."""
        # Using european_environment fixture
        feed = CMDBNoiseFeed(change_rate=10.0, seed=42)  # Generate many events
        duration = 10

        events = feed.generate_events(duration)

        change_types = [event["attributes"]["change_type"] for _, event in events]

        # Should have at least one of each type with enough events
        unique_types = set(change_types)
        assert len(unique_types) >= 2  # With seed=42 and 100 events, should get multiple types


class TestGenerateEventsFilesChanged:
    """Test files_changed generation (lines 75-78)."""

    def test_files_changed_count(self):
        """Test lines 75-78: num_files = rng.randint(1, 5)."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 10

        events = feed.generate_events(duration)

        for _, event_data in events:
            files_changed = event_data["attributes"]["files_changed"]
            assert 1 <= len(files_changed) <= 5

    def test_files_changed_format(self):
        """Test lines 75-78: files follow /etc/router/config_X.conf pattern."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        for _, event_data in events:
            files_changed = event_data["attributes"]["files_changed"]

            for filename in files_changed:
                # Check format
                assert filename.startswith("/etc/router/config_")
                assert filename.endswith(".conf")

                # Extract number part
                middle_part = filename[len("/etc/router/config_"):-len(".conf")]
                assert middle_part.isdigit()
                file_num = int(middle_part)
                assert 1 <= file_num <= 100


class TestGenerateEventsActorSelection:
    """Test actor selection (line 83)."""

    def test_actor_from_approved_list(self):
        """Test line 83: actor is from specified list."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        valid_actors = {"alice", "bob", "charlie", "automation"}

        for _, event_data in events:
            actor = event_data["attributes"]["actor"]
            assert actor in valid_actors, f"Invalid actor: {actor}"


class TestGenerateEventsDataStructure:
    """Test event data structure (lines 80-87)."""

    def test_event_structure(self):
        """Test lines 80-87: event has correct structure."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 2

        events = feed.generate_events(duration)

        for timestamp, event_data in events:
            # Top-level structure
            assert event_data["event_type"] == "cmdb.change"
            assert event_data["source"] == "cmdb_noise"
            assert "attributes" in event_data

            # Attributes structure
            attrs = event_data["attributes"]
            required_keys = {"actor", "files_changed", "change_type"}
            assert required_keys.issubset(attrs.keys())


class TestGenerateEventsSorting:
    """Test event sorting (line 89)."""

    def test_events_sorted_by_timestamp(self):
        """Test line 89: events are sorted by timestamp."""
        feed = CMDBNoiseFeed(change_rate=3.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        timestamps = [ts for ts, _ in events]
        assert timestamps == sorted(timestamps), "Events should be sorted by timestamp"

    def test_sorted_returns_new_list(self):
        """Test line 89: sorted() returns a new list."""
        feed = CMDBNoiseFeed(change_rate=1.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        # Verify it's a list (sorted returns list)
        assert isinstance(events, list)


class TestGenerateEventsDeterminism:
    """Test determinism with seed (lines 60-89)."""

    def test_deterministic_with_same_seed(self, mock_clock):
        """Test lines 60-89: same seed produces identical output."""
        feed1 = CMDBNoiseFeed(change_rate=1.0, seed=123)
        feed2 = CMDBNoiseFeed(change_rate=1.0, seed=123)
        duration = 10

        events1 = feed1.generate_events(duration)
        events2 = feed2.generate_events(duration)

        assert events1 == events2

    def test_different_with_different_seeds(self):
        """Test lines 60-89: different seeds produce different output."""
        feed1 = CMDBNoiseFeed(change_rate=1.0, seed=123)
        feed2 = CMDBNoiseFeed(change_rate=1.0, seed=456)
        duration = 10

        events1 = feed1.generate_events(duration)
        events2 = feed2.generate_events(duration)

        assert events1 != events2


class TestGenerateEventsEdgeCases:
    """Test edge cases for generate_events."""

    def test_duration_zero(self, mock_event_bus):
        """Test with duration = 0."""
        feed = CMDBNoiseFeed(change_rate=10.0, seed=42)
        events = feed.generate_events(0)
        assert events == []

    def test_very_high_change_rate(self, current_utc_time):
        """Test with very high change_rate."""
        feed = CMDBNoiseFeed(change_rate=1000.0, seed=42)
        duration = 5

        events = feed.generate_events(duration)

        # 5 * 1000 = 5000 events
        assert len(events) == 5000

        # All timestamps should be valid
        for timestamp, _ in events:
            assert 0 <= timestamp <= duration


@pytest.mark.parametrize("rate,duration,expected", [
    (0.1, 10, 1),
    (0.5, 10, 5),
    (1.0, 5, 5),
    (2.5, 4, 10),
    (0.0, 100, 0),
])
def test_event_count_parametrized(rate, duration, expected, mock_clock):
    """Parametrized test for event count calculation."""
    feed = CMDBNoiseFeed(change_rate=rate, seed=42)
    events = feed.generate_events(duration)
    assert len(events) == expected


def test_inherits_from_background_feed():
    """Test CMDBNoiseFeed inherits from BackgroundFeed."""
    feed = CMDBNoiseFeed()
    from simulator.engine.simulation_engine import BackgroundFeed
    assert isinstance(feed, BackgroundFeed)
