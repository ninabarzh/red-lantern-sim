"""Unit tests for RouteViews feed with European defaults."""
import os
import pytest
from unittest.mock import patch
from simulator.feeds.bgp.routeviews_feed import RouteViewsFeedMock, EUROPEAN_COLLECTORS


@pytest.mark.unit
class TestRouteViewsFeedMock:
    """Test RouteViews feed mock functionality with European defaults."""

    def test_default_european_initialisation(self) -> None:
        """Test that the mock defaults to European collector."""
        # Clear environment variables for this test to ensure defaults
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()
            assert feed.collector == "route-views.amsix"  # Amsterdam default
            assert feed.peer_ip == "193.0.0.56"  # European IP

    def test_custom_initialisation(self) -> None:
        """Test that custom values override defaults."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock(
                collector="route-views.linx",  # London
                peer_ip="192.0.2.1"
            )
            assert feed.collector == "route-views.linx"
            assert feed.peer_ip == "192.0.2.1"

    def test_environment_variable_collector(self) -> None:
        """Test that environment variable overrides default."""
        with patch.dict(os.environ, {"ROUTEVIEWS_COLLECTOR": "route-views.linx"}):
            feed = RouteViewsFeedMock()
            assert feed.collector == "route-views.linx"  # From env var
            assert feed.peer_ip == "193.0.0.56"  # Still default

    def test_environment_variable_peer_ip(self) -> None:
        """Test that environment variable overrides default peer IP."""
        with patch.dict(os.environ, {"ROUTEVIEWS_PEER_IP": "198.51.100.1"}, clear=True):
            feed = RouteViewsFeedMock()
            assert feed.collector == "route-views.amsix"  # Still default
            assert feed.peer_ip == "198.51.100.1"  # From env var

    def test_generate_update_basic(self) -> None:
        """Test basic BGP update generation."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()

            update = feed.generate_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1"
            )

            assert update["type"] == "bgp4mp_message"
            assert update["subtype"] == "update"
            assert update["collector"] == "route-views.amsix"  # European
            assert update["announced_prefixes"] == ["203.0.113.0/24"]
            assert update["as_path"] == [6939, 64500]
            assert update["origin_as"] == 64500

    def test_generate_update_london_collector(self) -> None:
        """Test BGP update with London collector."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock(collector="route-views.linx")

            update = feed.generate_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1"
            )

            assert update["collector"] == "route-views.linx"  # London
            assert update["peer_ip"] == "193.0.0.56"

    def test_generate_update_with_attributes(self) -> None:
        """Test BGP update with additional attributes."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()

            update = feed.generate_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1",
                attributes={"local_pref": 100, "med": 50}
            )

            assert "attributes" in update
            assert update["attributes"]["local_pref"] == 100
            assert update["attributes"]["med"] == 50

    def test_generate_withdrawal(self) -> None:
        """Test BGP withdrawal generation."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()

            withdrawal = feed.generate_withdrawal(
                timestamp=1700000000,
                prefix="203.0.113.0/24"
            )

            assert withdrawal["type"] == "bgp4mp_message"
            assert withdrawal["subtype"] == "update"
            assert withdrawal["withdrawn_prefixes"] == ["203.0.113.0/24"]
            assert withdrawal["collector"] == "route-views.amsix"  # European

    def test_to_telemetry_event_static_method(self) -> None:
        """Test static conversion to telemetry format."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()
            update = feed.generate_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1"
            )

            telemetry = RouteViewsFeedMock.to_telemetry_event(
                routeviews_message=update,
                scenario_name="test-scenario",
                attack_step="announce"
            )

            assert telemetry["event_type"] == "bgp.update"
            assert telemetry["timestamp"] == 1700000000
            assert telemetry["attributes"]["prefix"] == "203.0.113.0/24"
            assert telemetry["source"]["observer"] == "route-views.amsix"
            assert telemetry["scenario"]["name"] == "test-scenario"

    def test_convenience_functions_european_default(self) -> None:
        """Test convenience functions with European default."""
        from simulator.feeds.bgp.routeviews_feed import mock_routeviews_update

        with patch.dict(os.environ, {}, clear=True):
            event = mock_routeviews_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1"
                # No collector specified - should use European default
            )

            assert event["event_type"] == "bgp.update"
            assert event["source"]["feed"] == "routeviews"
            assert event["source"]["observer"] == "route-views.amsix"  # European

    def test_convenience_functions_custom_collector(self) -> None:
        """Test convenience functions with custom collector."""
        from simulator.feeds.bgp.routeviews_feed import mock_routeviews_update

        # Even with env var set, explicit collector should take precedence
        with patch.dict(os.environ, {"ROUTEVIEWS_COLLECTOR": "route-views.amsix"}):
            event = mock_routeviews_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[6939, 64500],
                next_hop="198.32.176.1",
                collector="route-views.linx"  # Specify London
            )

            assert event["source"]["observer"] == "route-views.linx"  # Custom

    def test_european_collectors_constant(self) -> None:
        """Test that European collectors constant is available."""
        assert "amsterdam" in EUROPEAN_COLLECTORS
        assert "london" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["amsterdam"] == "route-views.amsix"
        assert EUROPEAN_COLLECTORS["london"] == "route-views.linx"
