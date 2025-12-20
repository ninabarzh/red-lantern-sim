"""
RouteViews feed mock.

This module simulates BGP data as it would appear from University of Oregon's
RouteViews project. RouteViews provides BGP routing tables and UPDATE messages
from collectors around the world.

For simulation purposes, we generate RouteViews-style MRT (Multi-Threaded Routing Toolkit)
formatted data, converted to our telemetry schema.
"""

from typing import Dict, Any, List, Optional
import json


class RouteViewsFeedMock:
    """
    Mock RouteViews BGP feed generator.

    Produces BGP messages in a format similar to RouteViews collectors.
    """

    def __init__(
        self,
        collector: str = "route-views.oregon-ix.net",
        peer_ip: str = "198.32.176.1",
    ):
        """
        Args:
            collector: RouteViews collector hostname
            peer_ip: IP address of the BGP peer
        """
        self.collector = collector
        self.peer_ip = peer_ip

    def generate_table_dump(
        self,
        timestamp: int,
        prefix: str,
        as_path: List[int],
        next_hop: str,
        local_pref: Optional[int] = None,
        med: Optional[int] = None,
        atomic_aggregate: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate a RouteViews routing table entry.

        Args:
            timestamp: Unix timestamp
            prefix: IP prefix
            as_path: List of AS numbers
            next_hop: Next hop IP
            local_pref: LOCAL_PREF attribute
            med: MED (Multi-Exit Discriminator) attribute
            atomic_aggregate: ATOMIC_AGGREGATE flag

        Returns:
            Dict representing routing table entry
        """
        entry = {
            "type": "table_dump_v2",
            "timestamp": timestamp,
            "collector": self.collector,
            "peer_ip": self.peer_ip,
            "prefix": prefix,
            "prefix_length": int(prefix.split("/")[1]),
            "as_path": as_path,
            "origin_as": as_path[-1] if as_path else None,
            "next_hop": next_hop,
            "atomic_aggregate": atomic_aggregate,
        }

        if local_pref is not None:
            entry["local_pref"] = local_pref
        if med is not None:
            entry["med"] = med

        return entry

    def generate_update(
        self,
        timestamp: int,
        prefix: str,
        as_path: List[int],
        next_hop: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a RouteViews BGP UPDATE message.

        Args:
            timestamp: Unix timestamp
            prefix: IP prefix
            as_path: AS-PATH
            next_hop: Next hop IP
            attributes: Additional BGP attributes

        Returns:
            Dict representing UPDATE message
        """
        message = {
            "type": "bgp4mp_message",
            "subtype": "update",
            "timestamp": timestamp,
            "collector": self.collector,
            "peer_ip": self.peer_ip,
            "announced_prefixes": [prefix],
            "as_path": as_path,
            "origin_as": as_path[-1] if as_path else None,
            "next_hop": next_hop,
        }

        if attributes:
            message["attributes"] = attributes

        return message

    def generate_withdrawal(
        self,
        timestamp: int,
        prefix: str,
    ) -> Dict[str, Any]:
        """
        Generate a RouteViews BGP WITHDRAWAL message.

        Args:
            timestamp: Unix timestamp
            prefix: Prefix being withdrawn

        Returns:
            Dict representing WITHDRAWAL message
        """
        return {
            "type": "bgp4mp_message",
            "subtype": "update",
            "timestamp": timestamp,
            "collector": self.collector,
            "peer_ip": self.peer_ip,
            "withdrawn_prefixes": [prefix],
        }

    def to_telemetry_event(
        self,
        routeviews_message: Dict[str, Any],
        scenario_name: Optional[str] = None,
        attack_step: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convert RouteViews message to Red Lantern telemetry format.

        Args:
            routeviews_message: RouteViews-formatted message
            scenario_name: Optional scenario identifier
            attack_step: Optional attack step identifier

        Returns:
            Telemetry event compatible with Wazuh rules
        """
        # Determine event type
        if "withdrawn_prefixes" in routeviews_message:
            event_type = "bgp.withdraw"
            attributes = {
                "prefix": routeviews_message["withdrawn_prefixes"][0],
                "withdrawn_from_peer": routeviews_message["peer_ip"],
            }
        elif "announced_prefixes" in routeviews_message:
            event_type = "bgp.update"
            attributes = {
                "prefix": routeviews_message["announced_prefixes"][0],
                "as_path": routeviews_message["as_path"],
                "origin_as": routeviews_message["origin_as"],
                "next_hop": routeviews_message["next_hop"],
            }

            # Add optional attributes
            for attr in ["local_pref", "med", "atomic_aggregate"]:
                if attr in routeviews_message:
                    attributes[attr] = routeviews_message[attr]
        else:
            # Table dump
            event_type = "bgp.table_entry"
            attributes = {
                "prefix": routeviews_message["prefix"],
                "as_path": routeviews_message["as_path"],
                "origin_as": routeviews_message["origin_as"],
                "next_hop": routeviews_message["next_hop"],
            }

        event = {
            "event_type": event_type,
            "timestamp": routeviews_message["timestamp"],
            "source": {
                "feed": "routeviews",
                "observer": routeviews_message["collector"],
            },
            "attributes": attributes,
        }

        if scenario_name or attack_step:
            event["scenario"] = {
                "name": scenario_name,
                "attack_step": attack_step,
            }

        return event


# Convenience functions


def mock_routeviews_update(
    timestamp: int,
    prefix: str,
    as_path: List[int],
    next_hop: str,
    collector: str = "route-views.oregon-ix.net",
    **kwargs,
) -> Dict[str, Any]:
    """Generate a mock RouteViews UPDATE in telemetry format."""
    feed = RouteViewsFeedMock(collector=collector)
    rv_msg = feed.generate_update(timestamp, prefix, as_path, next_hop, **kwargs)
    return feed.to_telemetry_event(rv_msg)


def mock_routeviews_withdrawal(
    timestamp: int,
    prefix: str,
    collector: str = "route-views.oregon-ix.net",
) -> Dict[str, Any]:
    """Generate a mock RouteViews WITHDRAWAL in telemetry format."""
    feed = RouteViewsFeedMock(collector=collector)
    rv_msg = feed.generate_withdrawal(timestamp, prefix)
    return feed.to_telemetry_event(rv_msg)


if __name__ == "__main__":
    # Example usage
    feed = RouteViewsFeedMock()

    # Generate UPDATE
    update = feed.generate_update(
        timestamp=1700000000,
        prefix="203.0.113.0/24",
        as_path=[6939, 174, 64500],
        next_hop="198.32.176.1",
        attributes={"local_pref": 100, "med": 0},
    )

    print("RouteViews UPDATE:")
    print(json.dumps(update, indent=2))

    # Convert to telemetry
    telemetry = feed.to_telemetry_event(update, scenario_name="test")
    print("\nTelemetry format:")
    print(json.dumps(telemetry, indent=2))
