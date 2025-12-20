"""Unit tests for mock Configuration Management Database."""
import pytest
from datetime import datetime, timedelta, UTC
from simulator.feeds.change_mgmt.mock_cmdb import MockCMDB


@pytest.mark.unit
class TestMockCMDB:
    """Test mock CMDB functionality."""

    def test_initialisation(self) -> None:
        """Test that CMDB initialises with empty state."""
        cmdb = MockCMDB()
        assert cmdb.changes == {}
        assert cmdb.change_counter == 1000

    def test_create_change_ticket(self) -> None:
        """Test creating a change management ticket."""
        cmdb = MockCMDB()
        now = datetime.now(UTC)

        ticket_id = cmdb.create_change_ticket(
            change_type="bgp_policy",
            description="Test BGP policy update",
            requester="alice@example.com",
            start_time=now,
            end_time=now + timedelta(hours=2),
            affected_prefixes=["203.0.113.0/24", "198.51.100.0/24"],
            affected_systems=["router-core-01"],
            status="approved",
            risk="medium"
        )

        # Verify ticket was created
        assert ticket_id.startswith("CHG-")
        assert ticket_id in cmdb.changes

        ticket = cmdb.changes[ticket_id]
        assert ticket["change_type"] == "bgp_policy"
        assert ticket["status"] == "approved"
        assert ticket["risk"] == "medium"
        assert "203.0.113.0/24" in ticket["affected_prefixes"]

    def test_change_authorisation_within_window(self) -> None:
        """Test authorised change within time window."""
        cmdb = MockCMDB()
        now = datetime.now(UTC)

        # Create an approved change ticket
        cmdb.create_change_ticket(
            change_type="bgp_policy",
            description="Authorised change",
            requester="network-team",
            start_time=now,
            end_time=now + timedelta(hours=1),
            affected_prefixes=["203.0.113.0/24"],
            status="approved"
        )

        # Check authorisation during the window
        is_authorised = cmdb.is_change_authorised(
            change_type="bgp_policy",
            timestamp=now + timedelta(minutes=30),
            prefix="203.0.113.0/24"
        )

        assert is_authorised is True

    def test_change_not_authorised_outside_window(self) -> None:
        """Test change not authorised outside time window."""
        cmdb = MockCMDB()
        now = datetime.now(UTC)

        cmdb.create_change_ticket(
            change_type="bgp_policy",
            description="Past change",
            requester="network-team",
            start_time=now,
            end_time=now + timedelta(hours=1),
            affected_prefixes=["203.0.113.0/24"],
            status="approved"
        )

        # Check after the window has ended
        is_authorised = cmdb.is_change_authorised(
            change_type="bgp_policy",
            timestamp=now + timedelta(hours=2),
            prefix="203.0.113.0/24"
        )

        assert is_authorised is False

    def test_generate_telemetry_event(self) -> None:
        """Test telemetry event generation from a ticket."""
        cmdb = MockCMDB()
        now = datetime.now(UTC)

        ticket_id = cmdb.create_change_ticket(
            change_type="bgp_policy",
            description="Test telemetry generation",
            requester="monitoring@example.com",
            start_time=now,
            end_time=now + timedelta(hours=1),
            affected_prefixes=["203.0.113.0/24"],
            status="approved"
        )

        telemetry = cmdb.generate_telemetry_event(
            ticket_id=ticket_id,
            scenario_name="test-scenario"
        )

        assert telemetry["event_type"] == "change_mgmt.ticket"
        assert telemetry["attributes"]["ticket_id"] == ticket_id
        assert telemetry["attributes"]["status"] == "approved"

    def test_get_active_changes(self) -> None:
        """Test retrieving active changes at a given time."""
        cmdb = MockCMDB()
        now = datetime.now(UTC)

        # Create two tickets - one active, one future
        cmdb.create_change_ticket(
            change_type="bgp_policy",
            description="Active change",
            requester="team-a",
            start_time=now - timedelta(minutes=30),
            end_time=now + timedelta(minutes=30),
            status="approved"
        )

        cmdb.create_change_ticket(
            change_type="maintenance",
            description="Future change",
            requester="team-b",
            start_time=now + timedelta(hours=1),
            end_time=now + timedelta(hours=2),
            status="approved"
        )

        # Should only get the active change
        active_changes = cmdb.get_active_changes(now)
        assert len(active_changes) == 1
        assert active_changes[0]["description"] == "Active change"
