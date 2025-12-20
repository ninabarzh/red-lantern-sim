"""Unit tests for RIPE RIS feed."""

import pytest

from simulator.feeds.bgp.ris_feed import (
    RISFeedMock,
    mock_ris_update,
    mock_ris_withdrawal,
)


@pytest.mark.unit
class TestRISFeedMock:
    """Test RIPE RIS feed mock functionality."""

    def test_initialisation_defaults(self) -> None:
        """Test that the mock initialises with correct defaults."""
        feed = RISFeedMock()
        assert feed.collector == "rrc00"
        assert feed.peer_asn == 3333

    def test_initialisation_custom_values(self) -> None:
        """Test that custom values are correctly set."""
        feed = RISFeedMock(collector="rrc01", peer_asn=64500)
        assert feed.collector == "rrc01"
        assert feed.peer_asn == 64500

    def test_generate_update_basic(self) -> None:
        """Test basic RIS UPDATE generation."""
        feed = RISFeedMock(collector="rrc00", peer_asn=3333)

        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            origin="IGP",
            next_hop="192.0.2.1",
        )

        assert update["type"] == "UPDATE"
        assert update["collector"] == "rrc00"
        assert update["peer_asn"] == 3333
        assert update["timestamp"] == 1700000000
        assert update["path"] == [3333, 64500]
        assert update["origin"] == "IGP"
        assert update["announcements"][0]["prefixes"] == ["203.0.113.0/24"]
        assert update["announcements"][0]["next_hop"] == "192.0.2.1"
        assert update["id"] == "rrc00-1700000000-203.0.113.0/24"
        assert update["host"] == "rrc00.ripe.net"

    def test_generate_update_default_next_hop(self) -> None:
        """Test UPDATE generation with default next hop."""
        feed = RISFeedMock()

        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            # No next_hop specified, should use default
        )

        assert update["announcements"][0]["next_hop"] == "192.0.2.1"

    def test_generate_update_custom_next_hop(self) -> None:
        """Test UPDATE generation with custom next hop."""
        feed = RISFeedMock()

        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            next_hop="198.51.100.1",
        )

        assert update["announcements"][0]["next_hop"] == "198.51.100.1"

    def test_generate_update_with_communities(self) -> None:
        """Test UPDATE generation with BGP communities."""
        feed = RISFeedMock()

        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            communities=["3333:100", "64500:200", "64500:300"],
        )

        assert "communities" in update
        assert update["communities"] == [[3333, 100], [64500, 200], [64500, 300]]

    def test_generate_update_without_communities(self) -> None:
        """Test UPDATE generation without communities."""
        feed = RISFeedMock()

        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            # No communities parameter
        )

        assert "communities" not in update

    def test_generate_update_different_origin(self) -> None:
        """Test UPDATE generation with different BGP origin types."""
        feed = RISFeedMock()

        # Test IGP origin (default)
        update_igp = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            origin="IGP",
        )
        assert update_igp["origin"] == "IGP"

        # Test EGP origin
        update_egp = feed.generate_update(
            timestamp=1700000001,
            prefix="198.51.100.0/24",
            as_path=[3333, 64500],
            origin="EGP",
        )
        assert update_egp["origin"] == "EGP"

        # Test INCOMPLETE origin
        update_incomplete = feed.generate_update(
            timestamp=1700000002,
            prefix="192.0.2.0/24",
            as_path=[3333, 64500],
            origin="INCOMPLETE",
        )
        assert update_incomplete["origin"] == "INCOMPLETE"

    def test_generate_withdrawal(self) -> None:
        """Test RIS WITHDRAWAL generation."""
        feed = RISFeedMock(collector="rrc01", peer_asn=64500)

        withdrawal = feed.generate_withdrawal(
            timestamp=1700000000, prefix="203.0.113.0/24"
        )

        assert withdrawal["type"] == "WITHDRAWAL"
        assert withdrawal["collector"] == "rrc01"
        assert withdrawal["peer_asn"] == 64500
        assert withdrawal["timestamp"] == 1700000000
        assert withdrawal["withdrawals"] == ["203.0.113.0/24"]
        assert withdrawal["id"] == "rrc01-1700000000-203.0.113.0/24-withdraw"
        assert withdrawal["host"] == "rrc01.ripe.net"

    def test_to_telemetry_event_update(self) -> None:
        """Test conversion of UPDATE to telemetry format."""
        feed = RISFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            origin="IGP",
            next_hop="192.0.2.1",
            communities=["3333:100", "64500:200"],
        )

        telemetry = RISFeedMock.to_telemetry_event(
            update, scenario_name="test-scenario", attack_step="announce"
        )

        assert telemetry["event_type"] == "bgp.update"
        assert telemetry["timestamp"] == 1700000000
        assert telemetry["source"]["feed"] == "ris"
        assert telemetry["source"]["observer"] == "rrc00"
        assert telemetry["attributes"]["prefix"] == "203.0.113.0/24"
        assert telemetry["attributes"]["as_path"] == [3333, 64500]
        assert telemetry["attributes"]["origin_as"] == 64500
        assert telemetry["attributes"]["next_hop"] == "192.0.2.1"
        assert telemetry["attributes"]["origin_type"] == "IGP"
        assert telemetry["attributes"]["communities"] == ["3333:100", "64500:200"]
        assert telemetry["scenario"]["name"] == "test-scenario"
        assert telemetry["scenario"]["attack_step"] == "announce"

    def test_to_telemetry_event_update_no_communities(self) -> None:
        """Test UPDATE to telemetry conversion without communities."""
        feed = RISFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[3333, 64500],
            # No communities
        )

        telemetry = RISFeedMock.to_telemetry_event(update)

        assert telemetry["event_type"] == "bgp.update"
        assert "communities" not in telemetry["attributes"]

    def test_to_telemetry_event_withdrawal(self) -> None:
        """Test conversion of WITHDRAWAL to telemetry format."""
        feed = RISFeedMock(peer_asn=64500)
        withdrawal = feed.generate_withdrawal(
            timestamp=1700000000, prefix="203.0.113.0/24"
        )

        telemetry = RISFeedMock.to_telemetry_event(
            withdrawal, scenario_name="test-scenario", attack_step="withdraw"
        )

        assert telemetry["event_type"] == "bgp.withdraw"
        assert telemetry["timestamp"] == 1700000000
        assert telemetry["source"]["feed"] == "ris"
        assert telemetry["source"]["observer"] == "rrc00"
        assert telemetry["attributes"]["prefix"] == "203.0.113.0/24"
        assert telemetry["attributes"]["withdrawn_by_peer"] == 64500
        assert telemetry["scenario"]["name"] == "test-scenario"
        assert telemetry["scenario"]["attack_step"] == "withdraw"

    def test_to_telemetry_event_empty_as_path(self) -> None:
        """Test conversion with empty AS path."""
        feed = RISFeedMock()
        update = feed.generate_update(
            timestamp=1700000000,
            prefix="203.0.113.0/24",
            as_path=[],  # Empty path
            origin="IGP",
        )

        telemetry = RISFeedMock.to_telemetry_event(update)

        assert telemetry["attributes"]["origin_as"] is None
        assert telemetry["attributes"]["as_path"] == []

    def test_mock_ris_update_function(self) -> None:
        """Test the convenience function for RIS UPDATE."""
        # Test with default collector
        telemetry1 = mock_ris_update(
            timestamp=1700000000, prefix="203.0.113.0/24", as_path=[3333, 64500]
        )

        assert telemetry1["event_type"] == "bgp.update"
        assert telemetry1["source"]["observer"] == "rrc00"

        # Test with custom collector
        telemetry2 = mock_ris_update(
            timestamp=1700000001,
            prefix="198.51.100.0/24",
            as_path=[3333, 64500],
            collector="rrc01",
            origin="EGP",
            next_hop="198.51.100.1",
        )

        assert telemetry2["source"]["observer"] == "rrc01"
        assert telemetry2["attributes"]["origin_type"] == "EGP"
        assert telemetry2["attributes"]["next_hop"] == "198.51.100.1"

    def test_mock_ris_withdrawal_function(self) -> None:
        """Test the convenience function for RIS WITHDRAWAL."""
        # Test with default collector
        telemetry1 = mock_ris_withdrawal(timestamp=1700000000, prefix="203.0.113.0/24")

        assert telemetry1["event_type"] == "bgp.withdraw"
        assert telemetry1["source"]["observer"] == "rrc00"

        # Test with custom collector
        telemetry2 = mock_ris_withdrawal(
            timestamp=1700000001, prefix="198.51.100.0/24", collector="rrc01"
        )

        assert telemetry2["source"]["observer"] == "rrc01"

    def test_generate_update_edge_cases(self) -> None:
        """Test UPDATE generation with edge cases."""
        feed = RISFeedMock()

        # Test with IPv6 prefix
        update_ipv6 = feed.generate_update(
            timestamp=1700000000, prefix="2001:db8::/32", as_path=[3333, 64500]
        )

        assert update_ipv6["announcements"][0]["prefixes"] == ["2001:db8::/32"]

        # Test with long AS path
        update_long_path = feed.generate_update(
            timestamp=1700000001,
            prefix="203.0.113.0/24",
            as_path=[3333, 174, 2914, 64500, 64501, 64502],
        )

        assert len(update_long_path["path"]) == 6
        assert update_long_path["path"][-1] == 64502


@pytest.mark.unit
class TestRISFeedMockStaticMethod:
    """Test static method functionality."""

    def test_to_telemetry_event_is_static(self) -> None:
        """Verify that to_telemetry_event is a static method."""
        # Should be callable without instance
        update = {
            "type": "UPDATE",
            "timestamp": 1700000000,
            "collector": "rrc00",
            "peer_asn": 3333,
            "announcements": [
                {"prefixes": ["203.0.113.0/24"], "next_hop": "192.0.2.1"}
            ],
            "path": [3333, 64500],
            "origin": "IGP",
        }

        telemetry = RISFeedMock.to_telemetry_event(update)
        assert telemetry["event_type"] == "bgp.update"

    def test_to_telemetry_event_invalid_message(self) -> None:
        """Test error handling for invalid message types."""
        invalid_message = {"type": "INVALID_TYPE"}

        # Should raise KeyError when accessing missing fields
        with pytest.raises(KeyError):
            RISFeedMock.to_telemetry_event(invalid_message)


@pytest.mark.unit
def test_imports() -> None:
    """Test that all public exports are available."""
    from simulator.feeds.bgp.ris_feed import (
        RISFeedMock,
        mock_ris_update,
        mock_ris_withdrawal,
    )

    # Verify they can be instantiated/called
    feed = RISFeedMock()
    assert feed is not None

    # Verify functions exist
    assert callable(mock_ris_update)
    assert callable(mock_ris_withdrawal)


@pytest.mark.unit
def test_example_main_execution() -> None:
    """Test that the example usage in __main__ works correctly."""
    import subprocess
    import sys

    # Run the module as a script
    result = subprocess.run(
        [sys.executable, "-m", "simulator.feeds.bgp.ris_feed"],
        capture_output=True,
        text=True,
        cwd=".",  # Run from project root
    )

    # Should execute without errors
    assert result.returncode == 0
    assert "RIS UPDATE:" in result.stdout
    assert "Telemetry format:" in result.stdout
