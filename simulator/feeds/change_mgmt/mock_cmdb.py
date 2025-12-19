"""
Mock CMDB (Configuration Management Database) / Change Management System.

This module simulates a change management system (like ServiceNow, Jira, etc.)
that tracks approved changes to network infrastructure. In production, you would
query your actual CMDB API.

For simulation purposes, we generate mock change tickets that can be correlated
with BGP events to detect unauthorised changes.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uuid


class MockCMDB:
    """
    Mock Change Management Database.

    Tracks approved network changes and provides correlation data
    for detecting unauthorised BGP policy modifications.
    """

    def __init__(self):
        """Initialise with empty change database."""
        self.changes: Dict[str, Dict[str, Any]] = {}
        self.change_counter = 1000

    def create_change_ticket(
            self,
            change_type: str,
            description: str,
            requester: str,
            start_time: datetime,
            end_time: datetime,
            affected_prefixes: Optional[List[str]] = None,
            affected_systems: Optional[List[str]] = None,
            status: str = "approved",
            risk: str = "medium",
    ) -> str:
        """
        Create a mock change ticket.

        Args:
            change_type: Type of change (bgp_policy, roa_change, maintenance, etc.)
            description: Human-readable description
            requester: Username of requester
            start_time: Change window start
            end_time: Change window end
            affected_prefixes: List of IP prefixes affected
            affected_systems: List of systems affected
            status: Change status (draft, approved, implemented, closed)
            risk: Risk level (low, medium, high, critical)

        Returns:
            Change ticket ID (CHG-XXXXXX)
        """
        ticket_id = f"CHG-{self.change_counter:06d}"
        self.change_counter += 1

        self.changes[ticket_id] = {
            "ticket_id": ticket_id,
            "change_type": change_type,
            "description": description,
            "requester": requester,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "affected_prefixes": affected_prefixes or [],
            "affected_systems": affected_systems or [],
            "status": status,
            "risk": risk,
            "created_at": datetime.utcnow().isoformat(),
        }

        return ticket_id

    def is_change_authorised(
            self,
            change_type: str,
            timestamp: datetime,
            prefix: Optional[str] = None,
            system: Optional[str] = None,
    ) -> bool:
        """
        Check if a change is authorised at a given time.

        Args:
            change_type: Type of change to check
            timestamp: When the change occurred
            prefix: Optional prefix to check
            system: Optional system to check

        Returns:
            True if an approved change ticket exists covering this change
        """
        for ticket in self.changes.values():
            if ticket["status"] != "approved":
                continue

            if ticket["change_type"] != change_type:
                continue

            # Check time window
            start = datetime.fromisoformat(ticket["start_time"])
            end = datetime.fromisoformat(ticket["end_time"])

            if not (start <= timestamp <= end):
                continue

            # Check prefix if specified
            if prefix and ticket["affected_prefixes"]:
                if prefix not in ticket["affected_prefixes"]:
                    continue

            # Check system if specified
            if system and ticket["affected_systems"]:
                if system not in ticket["affected_systems"]:
                    continue

            # Match found
            return True

        return False

    def generate_telemetry_event(
            self,
            ticket_id: str,
            scenario_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a telemetry event for a change ticket.

        Args:
            ticket_id: Change ticket ID
            scenario_name: Optional scenario identifier

        Returns:
            Telemetry event compatible with Wazuh
        """
        if ticket_id not in self.changes:
            raise ValueError(f"Ticket {ticket_id} not found")

        ticket = self.changes[ticket_id]

        event = {
            "event_type": "change_mgmt.ticket",
            "timestamp": int(datetime.utcnow().timestamp()),
            "source": {
                "feed": "cmdb",
                "observer": "change_management_system",
            },
            "attributes": {
                "ticket_id": ticket["ticket_id"],
                "change_type": ticket["change_type"],
                "description": ticket["description"],
                "requester": ticket["requester"],
                "status": ticket["status"],
                "risk": ticket["risk"],
                "start_time": ticket["start_time"],
                "end_time": ticket["end_time"],
                "affected_prefixes": ticket["affected_prefixes"],
                "affected_systems": ticket["affected_systems"],
            },
        }

        if scenario_name:
            event["scenario"] = {"name": scenario_name}

        return event

    def get_active_changes(self, timestamp: datetime) -> List[Dict[str, Any]]:
        """
        Get all active change tickets at a given time.

        Args:
            timestamp: Time to check

        Returns:
            List of active change tickets
        """
        active = []

        for ticket in self.changes.values():
            start = datetime.fromisoformat(ticket["start_time"])
            end = datetime.fromisoformat(ticket["end_time"])

            if start <= timestamp <= end:
                active.append(ticket)

        return active


# Convenience functions

def generate_approved_bgp_change(
        prefix: str,
        start_offset_minutes: int = 0,
        duration_minutes: int = 60,
        requester: str = "network_ops",
) -> Dict[str, Any]:
    """
    Generate an approved BGP policy change ticket.

    Args:
        prefix: Affected IP prefix
        start_offset_minutes: Minutes from now for change window start
        duration_minutes: Duration of change window
        requester: Username of requester

    Returns:
        Change ticket as telemetry event
    """
    cmdb = MockCMDB()

    start_time = datetime.utcnow() + timedelta(minutes=start_offset_minutes)
    end_time = start_time + timedelta(minutes=duration_minutes)

    ticket_id = cmdb.create_change_ticket(
        change_type="bgp_policy",
        description=f"Planned BGP policy update for {prefix}",
        requester=requester,
        start_time=start_time,
        end_time=end_time,
        affected_prefixes=[prefix],
        status="approved",
        risk="medium",
    )

    return cmdb.generate_telemetry_event(ticket_id)


def generate_roa_change_ticket(
        prefix: str,
        start_offset_minutes: int = 0,
        duration_minutes: int = 30,
        requester: str = "security_team",
) -> Dict[str, Any]:
    """
    Generate an approved RPKI ROA change ticket.

    Args:
        prefix: Affected IP prefix
        start_offset_minutes: Minutes from now for change window start
        duration_minutes: Duration of change window
        requester: Username of requester

    Returns:
        Change ticket as telemetry event
    """
    cmdb = MockCMDB()

    start_time = datetime.utcnow() + timedelta(minutes=start_offset_minutes)
    end_time = start_time + timedelta(minutes=duration_minutes)

    ticket_id = cmdb.create_change_ticket(
        change_type="roa_change",
        description=f"RPKI ROA update for {prefix}",
        requester=requester,
        start_time=start_time,
        end_time=end_time,
        affected_prefixes=[prefix],
        affected_systems=["rpki_ca"],
        status="approved",
        risk="high",
    )

    return cmdb.generate_telemetry_event(ticket_id)


if __name__ == "__main__":
    # Example usage
    import json

    cmdb = MockCMDB()

    # Create approved change
    now = datetime.utcnow()
    ticket_id = cmdb.create_change_ticket(
        change_type="bgp_policy",
        description="Update peer filters for AS65001",
        requester="alice@example.com",
        start_time=now,
        end_time=now + timedelta(hours=2),
        affected_prefixes=["203.0.113.0/24"],
        affected_systems=["router-r1", "router-r2"],
        status="approved",
        risk="medium",
    )

    print(f"Created ticket: {ticket_id}")

    # Check authorisation
    is_authorised = cmdb.is_change_authorised(
        change_type="bgp_policy",
        timestamp=now + timedelta(minutes=30),
        prefix="203.0.113.0/24",
    )

    print(f"Change authorised: {is_authorised}")

    # Generate telemetry event
    event = cmdb.generate_telemetry_event(ticket_id)
    print("\nTelemetry event:")
    print(json.dumps(event, indent=2))
