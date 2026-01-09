"""Unit tests for RouteViews feed with European defaults."""

import os
from unittest.mock import patch

import pytest

from simulator.feeds.bgp.routeviews_feed import (
    EUROPEAN_COLLECTORS,
    RouteViewsFeedMock,
    mock_routeviews_update,
    mock_routeviews_withdrawal,
)


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
                peer_ip="192.0.2.1",
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
                next_hop="198.32.176.1",
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
                next_hop="198.32.176.1",
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
                attributes={"local_pref": 100, "med": 50},
            )

            assert "attributes" in update
            assert update["attributes"]["local_pref"] == 100
            assert update["attributes"]["med"] == 50

    def test_generate_withdrawal(self) -> None:
        """Test BGP withdrawal generation."""
        with patch.dict(os.environ, {}, clear=True):
            feed = RouteViewsFeedMock()

            withdrawal = feed.generate_withdrawal(
                timestamp=1700000000, prefix="203.0.113.0/24"
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
                next_hop="198.32.176.1",
            )

            telemetry = RouteViewsFeedMock.to_telemetry_event(
                routeviews_message=update,
                scenario_name="test-scenario",
                attack_step="announce",
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
                next_hop="198.32.176.1",
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
                collector="route-views.linx",  # Specify London
            )

            assert event["source"]["observer"] == "route-views.linx"  # Custom

    def test_european_collectors_constant(self) -> None:
        """Test that European collectors constant is available."""
        assert "amsterdam" in EUROPEAN_COLLECTORS
        assert "london" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["amsterdam"] == "route-views.amsix"
        assert EUROPEAN_COLLECTORS["london"] == "route-views.linx"


class TestRouteViewsFeedMockTableDump:
    """Tests for generate_table_dump method (lines 70-88)."""

    def test_generate_table_dump_basic(self):
        """Test basic table dump generation."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002, 65003],
            next_hop="198.51.100.1",
        )

        assert result["type"] == "table_dump_v2"
        assert result["timestamp"] == 1700000000
        assert result["collector"] == "route-views.amsix"
        assert result["prefix"] == "203.0.113.0/24"
        assert result["prefix_length"] == 24
        assert result["as_path"] == [65001, 65002, 65003]
        assert result["origin_as"] == 65003
        assert result["next_hop"] == "198.51.100.1"
        assert result["atomic_aggregate"] is False

    def test_generate_table_dump_with_local_pref(self):
        """Test table dump with LOCAL_PREF attribute."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            local_pref=150,
        )

        assert "local_pref" in result
        assert result["local_pref"] == 150

    def test_generate_table_dump_with_med(self):
        """Test table dump with MED attribute."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            med=50,
        )

        assert "med" in result
        assert result["med"] == 50

    def test_generate_table_dump_with_atomic_aggregate(self):
        """Test table dump with ATOMIC_AGGREGATE flag set."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            atomic_aggregate=True,
        )

        assert result["atomic_aggregate"] is True

    def test_generate_table_dump_with_all_attributes(self):
        """Test table dump with all optional attributes."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="192.0.2.0/25",
            as_path=[6939, 174, 64500],
            next_hop="198.32.176.1",
            local_pref=200,
            med=100,
            atomic_aggregate=True,
        )

        assert result["local_pref"] == 200
        assert result["med"] == 100
        assert result["atomic_aggregate"] is True
        assert result["prefix_length"] == 25

    def test_generate_table_dump_empty_as_path(self):
        """Test table dump with empty AS path."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[],
            next_hop="198.51.100.1",
        )

        assert result["as_path"] == []
        assert result["origin_as"] is None

    def test_generate_table_dump_with_none_local_pref(self):
        """Test that None local_pref is not included in output."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001],
            next_hop="198.51.100.1",
            local_pref=None,
        )

        assert "local_pref" not in result

    def test_generate_table_dump_with_none_med(self):
        """Test that None MED is not included in output."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001],
            next_hop="198.51.100.1",
            med=None,
        )

        assert "med" not in result


class TestToTelemetryEventTableDump:
    """Tests for to_telemetry_event with table dumps (lines 171-172)."""

    def test_to_telemetry_event_table_dump(self):
        """Test converting table dump to telemetry format."""
        feed = RouteViewsFeedMock()
        table_dump = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002, 65003],
            next_hop="198.51.100.1",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(table_dump)

        assert telemetry["event_type"] == "bgp.table_entry"
        assert telemetry["timestamp"] == 1700000000
        assert telemetry["source"]["feed"] == "routeviews"
        assert telemetry["source"]["observer"] == "route-views.amsix"
        assert telemetry["attributes"]["prefix"] == "203.0.113.0/24"
        assert telemetry["attributes"]["as_path"] == [65001, 65002, 65003]
        assert telemetry["attributes"]["origin_as"] == 65003
        assert telemetry["attributes"]["next_hop"] == "198.51.100.1"

    def test_to_telemetry_event_table_dump_with_scenario(self):
        """Test table dump conversion with scenario info (lines 188-192)."""
        feed = RouteViewsFeedMock()
        table_dump = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(
            table_dump,
            scenario_name="test_scenario",
            attack_step="initial_state",
        )

        assert "scenario" in telemetry
        assert telemetry["scenario"]["name"] == "test_scenario"
        assert telemetry["scenario"]["attack_step"] == "initial_state"


class TestToTelemetryEventWithScenario:
    """Tests for to_telemetry_event with scenario info (lines 188-192)."""

    def test_to_telemetry_event_update_with_scenario_name_only(self):
        """Test UPDATE with only scenario_name."""
        feed = RouteViewsFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(
            update,
            scenario_name="hijack_scenario",
        )

        assert "scenario" in telemetry
        assert telemetry["scenario"]["name"] == "hijack_scenario"
        assert telemetry["scenario"]["attack_step"] is None

    def test_to_telemetry_event_update_with_attack_step_only(self):
        """Test UPDATE with only attack_step."""
        feed = RouteViewsFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(
            update,
            attack_step="announcement",
        )

        assert "scenario" in telemetry
        assert telemetry["scenario"]["name"] is None
        assert telemetry["scenario"]["attack_step"] == "announcement"

    def test_to_telemetry_event_withdrawal_with_scenario(self):
        """Test WITHDRAWAL with scenario info."""
        feed = RouteViewsFeedMock()
        withdrawal = feed.generate_withdrawal(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(
            withdrawal,
            scenario_name="cleanup_scenario",
            attack_step="withdrawal_phase",
        )

        assert "scenario" in telemetry
        assert telemetry["scenario"]["name"] == "cleanup_scenario"
        assert telemetry["scenario"]["attack_step"] == "withdrawal_phase"

    def test_to_telemetry_event_without_scenario_info(self):
        """Test that scenario block is not added when both are None."""
        feed = RouteViewsFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
        )

        telemetry = RouteViewsFeedMock.to_telemetry_event(update)

        assert "scenario" not in telemetry


class TestConvenienceFunctionsWithCollector:
    """Tests for convenience functions with collector parameter (lines 255-261)."""

    def test_mock_routeviews_update_with_custom_collector(self):
        """Test mock_routeviews_update with custom collector."""
        result = mock_routeviews_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            collector="route-views.linx",
        )

        assert result["event_type"] == "bgp.update"
        assert result["source"]["observer"] == "route-views.linx"

    def test_mock_routeviews_update_with_env_collector(self):
        """Test mock_routeviews_update using environment variable."""
        with patch.dict(os.environ, {"ROUTEVIEWS_COLLECTOR": "route-views.saopaulo"}):
            result = mock_routeviews_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[65001, 65002],
                next_hop="198.51.100.1",
            )

            assert result["source"]["observer"] == "route-views.saopaulo"

    def test_mock_routeviews_update_default_collector(self):
        """Test mock_routeviews_update uses default Amsterdam collector."""
        with patch.dict(os.environ, {}, clear=True):
            result = mock_routeviews_update(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
                as_path=[65001, 65002],
                next_hop="198.51.100.1",
            )

            assert result["source"]["observer"] == "route-views.amsix"

    def test_mock_routeviews_withdrawal_with_custom_collector(self):
        """Test mock_routeviews_withdrawal with custom collector."""
        result = mock_routeviews_withdrawal(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            collector="route-views.fra",
        )

        assert result["event_type"] == "bgp.withdraw"
        assert result["source"]["observer"] == "route-views.fra"

    def test_mock_routeviews_withdrawal_with_env_collector(self):
        """Test mock_routeviews_withdrawal using environment variable."""
        with patch.dict(os.environ, {"ROUTEVIEWS_COLLECTOR": "route-views.paris"}):
            result = mock_routeviews_withdrawal(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
            )

            assert result["source"]["observer"] == "route-views.paris"

    def test_mock_routeviews_withdrawal_default_collector(self):
        """Test mock_routeviews_withdrawal uses default Amsterdam collector."""
        with patch.dict(os.environ, {}, clear=True):
            result = mock_routeviews_withdrawal(
                timestamp=1700000000,
                prefix="203.0.113.0/24",
            )

            assert result["source"]["observer"] == "route-views.amsix"


class TestConvenienceFunctionsWithAttributes:
    """Test convenience functions with additional attributes."""

    def test_mock_routeviews_update_with_attributes_kwarg(self):
        """Test mock_routeviews_update passes kwargs to generate_update."""
        result = mock_routeviews_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            attributes={"communities": ["65001:100"]},
        )

        # Note: attributes get passed through to the RouteViews message
        # but may not appear in final telemetry depending on implementation
        assert result["event_type"] == "bgp.update"


class TestEuropeanCollectors:
    """Tests for EUROPEAN_COLLECTORS constant."""

    def test_european_collectors_contains_amsterdam(self):
        """Test that Amsterdam collector is in the dictionary."""
        assert "amsterdam" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["amsterdam"] == "route-views.amsix"

    def test_european_collectors_contains_london(self):
        """Test that London collector is in the dictionary."""
        assert "london" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["london"] == "route-views.linx"

    def test_european_collectors_contains_frankfurt(self):
        """Test that Frankfurt collector is in the dictionary."""
        assert "frankfurt" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["frankfurt"] == "route-views.fra"

    def test_european_collectors_contains_paris(self):
        """Test that Paris collector is in the dictionary."""
        assert "paris" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["paris"] == "route-views.paris"

    def test_european_collectors_contains_cape_town(self):
        """Test that Cape Town collector is in the dictionary."""
        assert "cape_town" in EUROPEAN_COLLECTORS
        assert EUROPEAN_COLLECTORS["cape_town"] == "route-views.napafrica"


class TestEdgeCasesAndIntegration:
    """Additional edge case tests for better coverage."""

    def test_generate_update_with_attributes(self):
        """Test generate_update with additional attributes."""
        feed = RouteViewsFeedMock()

        result = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001, 65002],
            next_hop="198.51.100.1",
            attributes={"communities": ["65001:100", "65001:200"]},
        )

        assert "attributes" in result
        assert result["attributes"]["communities"] == ["65001:100", "65001:200"]

    def test_to_telemetry_event_update_with_optional_bgp_attributes(self):
        """Test telemetry conversion preserves optional BGP attributes."""
        # The feed variable is not needed since we're creating the message directly
        # Create a RouteViews message with optional attributes
        rv_message = {
            "type": "bgp4mp_message",
            "subtype": "update",
            "timestamp": 1700000000,
            "collector": "route-views.amsix",
            "peer_ip": "193.0.0.56",
            "announced_prefixes": ["203.0.113.0/24"],
            "as_path": [65001, 65002],
            "origin_as": 65002,
            "next_hop": "198.51.100.1",
            "local_pref": 150,
            "med": 50,
            "atomic_aggregate": True,
        }

        telemetry = RouteViewsFeedMock.to_telemetry_event(rv_message)

        # Verify optional attributes are included
        assert telemetry["attributes"]["local_pref"] == 150
        assert telemetry["attributes"]["med"] == 50
        assert telemetry["attributes"]["atomic_aggregate"] is True

    def test_different_prefix_lengths(self):
        """Test table dump generation with various prefix lengths."""
        feed = RouteViewsFeedMock()

        test_cases = [
            ("192.0.2.0/8", 8),
            ("192.0.2.0/16", 16),
            ("192.0.2.0/24", 24),
            ("192.0.2.0/32", 32),
            ("2001:db8::/32", 32),
            ("2001:db8::/48", 48),
        ]

        for prefix, expected_length in test_cases:
            result = feed.generate_table_dump(
                timestamp=1700000000,
                prefix=prefix,
                as_path=[65001],
                next_hop="198.51.100.1",
            )
            assert result["prefix_length"] == expected_length

    def test_single_as_in_path(self):
        """Test with single AS in path (origin AS only)."""
        feed = RouteViewsFeedMock()

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[65001],
            next_hop="198.51.100.1",
        )

        assert result["as_path"] == [65001]
        assert result["origin_as"] == 65001

    def test_long_as_path(self):
        """Test with long AS path."""
        feed = RouteViewsFeedMock()
        long_path = list(range(65001, 65020))

        result = feed.generate_table_dump(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=long_path,
            next_hop="198.51.100.1",
        )

        assert result["as_path"] == long_path
        assert result["origin_as"] == 65019
