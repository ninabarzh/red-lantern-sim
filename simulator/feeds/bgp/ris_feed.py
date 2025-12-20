"""
RIPE RIS (Routing Information Service) feed mock.

This module simulates BGP UPDATE messages as they would appear from
RIPE's route collectors (rrc00, rrc01, etc.). In production, you would
subscribe to RIS Live or query the RIPE Stat API.

For simulation purposes, we generate realistic-looking RIS messages
that match the schema and timing characteristics of real RIS data.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json


class RISFeedMock:
    """
    Mock RIPE RIS feed generator.

    Produces BGP UPDATE messages in a format similar to RIS Live.
    """

    def __init__(self, collector: str = "rrc00", peer_asn: int = 3333):
        """
        Args:
            collector: RIS collector ID (e.g., rrc00, rrc01)
            peer_asn: ASN of the peer reporting the route
        """
        self.collector = collector
        self.peer_asn = peer_asn

    def generate_update(
        self,
        timestamp: int,
        prefix: str,
        as_path: List[int],
        origin: str = "IGP",
        next_hop: Optional[str] = None,
        communities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a RIS-style BGP UPDATE message.

        Args:
            timestamp: Unix timestamp
            prefix: IP prefix (e.g., "203.0.113.0/24")
            as_path: List of AS numbers in the path
            origin: BGP origin type (IGP, EGP, INCOMPLETE)
            next_hop: Next hop IP address
            communities: List of BGP communities

        Returns:
            Dict matching RIS Live schema
        """
        message = {
            "type": "UPDATE",
            "timestamp": timestamp,
            "collector": self.collector,
            "peer": str(self.peer_asn),
            "peer_asn": self.peer_asn,
            "id": f"{self.collector}-{timestamp}-{prefix}",
            "host": f"{self.collector}.ripe.net",
            "announcements": [
                {
                    "next_hop": next_hop or "192.0.2.1",
                    "prefixes": [prefix],
                }
            ],
            "path": as_path,
            "origin": origin,
        }

        if communities:
            message["communities"] = [
                [int(c.split(":")[0]), int(c.split(":")[1])] for c in communities
            ]

        return message

    def generate_withdrawal(
        self,
        timestamp: int,
        prefix: str,
    ) -> Dict[str, Any]:
        """
        Generate a RIS-style BGP WITHDRAWAL message.

        Args:
            timestamp: Unix timestamp
            prefix: IP prefix being withdrawn

        Returns:
            Dict matching RIS Live schema
        """
        return {
            "type": "WITHDRAWAL",
            "timestamp": timestamp,
            "collector": self.collector,
            "peer": str(self.peer_asn),
            "peer_asn": self.peer_asn,
            "id": f"{self.collector}-{timestamp}-{prefix}-withdraw",
            "host": f"{self.collector}.ripe.net",
            "withdrawals": [prefix],
        }

    def to_telemetry_event(
        self,
        ris_message: Dict[str, Any],
        scenario_name: Optional[str] = None,
        attack_step: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convert RIS message to Red Lantern telemetry format.

        Args:
            ris_message: RIS-formatted message
            scenario_name: Optional scenario identifier
            attack_step: Optional attack step identifier

        Returns:
            Telemetry event compatible with Wazuh rules
        """
        event_type = "bgp.update" if ris_message["type"] == "UPDATE" else "bgp.withdraw"

        attributes: Dict[str, Any] = {}

        if ris_message["type"] == "UPDATE":
            # Extract announcement details
            announcement = ris_message["announcements"][0]
            attributes = {
                "prefix": announcement["prefixes"][0],
                "as_path": ris_message["path"],
                "origin_as": ris_message["path"][-1] if ris_message["path"] else None,
                "next_hop": announcement["next_hop"],
                "origin_type": ris_message.get("origin", "IGP"),
            }

            if "communities" in ris_message:
                attributes["communities"] = [
                    f"{c[0]}:{c[1]}" for c in ris_message["communities"]
                ]
        else:
            # Withdrawal
            attributes = {
                "prefix": ris_message["withdrawals"][0],
                "withdrawn_by_peer": ris_message["peer_asn"],
            }

        event = {
            "event_type": event_type,
            "timestamp": ris_message["timestamp"],
            "source": {
                "feed": "ris",
                "observer": ris_message["collector"],
            },
            "attributes": attributes,
        }

        if scenario_name or attack_step:
            event["scenario"] = {
                "name": scenario_name,
                "attack_step": attack_step,
            }

        return event


# Convenience functions for direct use


def mock_ris_update(
    timestamp: int,
    prefix: str,
    as_path: List[int],
    collector: str = "rrc00",
    **kwargs,
) -> Dict[str, Any]:
    """Generate a mock RIS UPDATE in telemetry format."""
    feed = RISFeedMock(collector=collector)
    ris_msg = feed.generate_update(timestamp, prefix, as_path, **kwargs)
    return feed.to_telemetry_event(ris_msg)


def mock_ris_withdrawal(
    timestamp: int,
    prefix: str,
    collector: str = "rrc00",
) -> Dict[str, Any]:
    """Generate a mock RIS WITHDRAWAL in telemetry format."""
    feed = RISFeedMock(collector=collector)
    ris_msg = feed.generate_withdrawal(timestamp, prefix)
    return feed.to_telemetry_event(ris_msg)


if __name__ == "__main__":
    # Example usage
    feed = RISFeedMock(collector="rrc00", peer_asn=3333)

    # Generate UPDATE
    update = feed.generate_update(
        timestamp=1700000000,
        prefix="203.0.113.0/24",
        as_path=[3333, 64500],
        communities=["3333:100", "64500:999"],
    )

    print("RIS UPDATE:")
    print(json.dumps(update, indent=2))

    # Convert to telemetry
    telemetry = feed.to_telemetry_event(update, scenario_name="test")
    print("\nTelemetry format:")
    print(json.dumps(telemetry, indent=2))
