"""Unit tests for BGP noise feed using pytest."""

import random

import pytest

from simulator.feeds.bgp.bgp_noise_feed import BGPNoiseFeed


class TestBGPNoiseFeedInit:
    """Test BGPNoiseFeed initialization."""

    def test_default_parameters(self):
        """Test default parameter values."""
        feed = BGPNoiseFeed()
        assert feed.update_rate == 0.5
        assert feed.seed == 42

    def test_custom_parameters(self):
        """Test custom parameter values."""
        feed = BGPNoiseFeed(update_rate=2.5, seed=999)
        assert feed.update_rate == 2.5
        assert feed.seed == 999

    @pytest.mark.parametrize(
        "rate,seed",
        [
            (0.0, 1),
            (1.0, 42),
            (100.0, 123),
            (0.001, 999),
        ],
    )
    def test_various_parameters(self, rate, seed):
        """Test initialization with various parameter combinations."""
        feed = BGPNoiseFeed(update_rate=rate, seed=seed)
        assert feed.update_rate == rate
        assert feed.seed == seed


class TestGenerateEvents:
    """Test generate_events method."""

    @pytest.fixture
    def feed(self):
        """Default feed for tests."""
        return BGPNoiseFeed(update_rate=1.0, seed=42)

    def test_returns_list(self, feed):
        """Test return type is list."""
        events = feed.generate_events(duration=10)
        assert isinstance(events, list)

    def test_event_count_calculation(self):
        """Test event count calculation."""
        # Different rates should produce different counts
        test_cases = [
            (0.5, 10, 5),  # 10 * 0.5 = 5
            (2.0, 5, 10),  # 5 * 2.0 = 10
            (0.0, 100, 0),  # 100 * 0.0 = 0
            (3.5, 2, 7),  # 2 * 3.5 = 7
        ]

        for rate, duration, expected_count in test_cases:
            feed = BGPNoiseFeed(update_rate=rate, seed=42)
            events = feed.generate_events(duration)
            assert (
                len(events) == expected_count
            ), f"Failed for rate={rate}, duration={duration}"

    def test_events_sorted_by_timestamp(self, feed):
        """Test events are chronologically sorted."""
        events = feed.generate_events(duration=5)
        timestamps = [ts for ts, _ in events]
        assert timestamps == sorted(timestamps)

    def test_timestamp_range(self, feed):
        """Test all timestamps are within valid range."""
        duration = 10
        events = feed.generate_events(duration)

        for timestamp, _ in events:
            assert 0 <= timestamp <= duration

    def test_event_structure(self, feed):
        """Test each event has correct structure."""
        events = feed.generate_events(duration=3)

        for timestamp, event in events:
            assert isinstance(timestamp, int)

            # Check event structure
            assert event["event_type"] == "bgp.update"
            assert event["source"] == "bgp_noise"

            # Check attributes
            attrs = event["attributes"]
            required_keys = {"prefix", "origin_as", "as_path", "next_hop"}
            assert required_keys.issubset(attrs.keys())

    def test_deterministic_with_same_seed(self):
        """Test same seed produces identical output."""
        feed1 = BGPNoiseFeed(update_rate=1.0, seed=123)
        feed2 = BGPNoiseFeed(update_rate=1.0, seed=123)

        events1 = feed1.generate_events(duration=5)
        events2 = feed2.generate_events(duration=5)

        assert events1 == events2

    def test_different_with_different_seeds(self):
        """Test different seeds produce different output."""
        feed1 = BGPNoiseFeed(update_rate=1.0, seed=123)
        feed2 = BGPNoiseFeed(update_rate=1.0, seed=456)

        events1 = feed1.generate_events(duration=5)
        events2 = feed2.generate_events(duration=5)

        assert events1 != events2


class TestHelperMethods:
    """Test private helper methods."""

    def test_random_prefix_static(self):
        """Test _random_prefix is a static method."""
        # Verify it's callable on the class, not instance
        rng = random.Random(42)
        prefix = BGPNoiseFeed._random_prefix(rng)
        assert isinstance(prefix, str)

    def test_random_prefix_format(self):
        """Test _random_prefix generates valid CIDR notation."""
        rng = random.Random(42)

        # Test multiple calls
        for _ in range(100):
            prefix = BGPNoiseFeed._random_prefix(rng)

            # Format: X.X.X.X/Y
            parts = prefix.split("/")
            assert len(parts) == 2

            # IP part
            ip_parts = parts[0].split(".")
            assert len(ip_parts) == 4
            for octet in ip_parts:
                assert 0 <= int(octet) <= 255

            # First octet not multicast/private (224-239, 240-255)
            first_octet = int(ip_parts[0])
            assert 1 <= first_octet <= 223

            # Prefix length
            prefix_len = int(parts[1])
            assert prefix_len in [24, 23, 22, 21, 20, 19, 16]

    def test_random_as_path_static(self):
        """Test _random_as_path is a static method."""
        rng = random.Random(42)
        as_path = BGPNoiseFeed._random_as_path(rng)
        assert isinstance(as_path, list)

    def test_random_as_path_format(self):
        """Test _random_as_path generates valid AS paths."""
        rng = random.Random(42)

        for _ in range(100):
            as_path = BGPNoiseFeed._random_as_path(rng)

            # Length
            assert 2 <= len(as_path) <= 6

            # ASN range
            for asn in as_path:
                assert isinstance(asn, int)
                assert 1000 <= asn <= 65000


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.parametrize("duration", [0, 1, 100, 10000])
    def test_various_durations(self, duration):
        """Test with various duration values."""
        feed = BGPNoiseFeed(update_rate=0.5, seed=42)
        events = feed.generate_events(duration)

        # Should not crash
        assert isinstance(events, list)

        # Check timestamps if there are events
        if events:
            for ts, _ in events:
                assert 0 <= ts <= duration

    def test_very_high_rate(self):
        """Test with very high update rate."""
        feed = BGPNoiseFeed(update_rate=1000.0, seed=42)
        events = feed.generate_events(duration=10)

        # 10 * 1000 = 10000 events
        assert len(events) == 10000

    def test_very_low_rate(self):
        """Test with very low update rate."""
        feed = BGPNoiseFeed(update_rate=0.001, seed=42)
        events = feed.generate_events(duration=1000)

        # 1000 * 0.001 = 1 event
        assert len(events) == 1

    def test_zero_duration(self):
        """Test duration = 0 produces empty list."""
        feed = BGPNoiseFeed(update_rate=10.0, seed=42)
        events = feed.generate_events(duration=0)
        assert events == []

    def test_zero_rate(self):
        """Test update_rate = 0 produces empty list."""
        feed = BGPNoiseFeed(update_rate=0.0, seed=42)
        events = feed.generate_events(duration=100)
        assert events == []


class TestIntegration:
    """Minimal integration-style tests."""

    def test_inherits_from_background_feed(self):
        """Test BGPNoiseFeed is a proper BackgroundFeed subclass."""
        feed = BGPNoiseFeed()
        from simulator.engine.simulation_engine import BackgroundFeed

        assert isinstance(feed, BackgroundFeed)

    def test_generate_events_signature(self):
        """Test method signature matches parent class."""
        feed = BGPNoiseFeed()
        # Should not raise NotImplementedError
        events = feed.generate_events(duration=5)
        assert isinstance(events, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
