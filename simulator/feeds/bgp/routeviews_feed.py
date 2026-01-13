"""
RouteViews feed mock.

This module simulates BGP data as it would appear from RouteViews collectors.
RouteViews provides BGP routing tables and UPDATE messages from collectors
around the world. European defaults are used unless overridden.

For simulation purposes, we generate RouteViews-style MRT (Multi-Threaded Routing Toolkit)
formatted data, converted to our telemetry schema.
"""

import json
import os
from typing import Any


class RouteViewsFeedMock:
    """
    Mock RouteViews BGP feed generator.

    Produces BGP messages in a format similar to RouteViews collectors.
    Uses European defaults (Amsterdam) unless specified otherwise.
    """

    def __init__(
        self,
        collector: str | None = None,
        peer_ip: str | None = None,
    ):
        """
        Args:
            collector: RouteViews collector hostname. Defaults to Amsterdam.
            peer_ip: IP address of the BGP peer. Defaults to European IP.
        """
        # Use European defaults unless specified
        self.collector = collector or os.getenv(
            "ROUTEVIEWS_COLLECTOR",
            "route-views.amsix",  # Amsterdam Internet Exchange
        )
        self.peer_ip = peer_ip or os.getenv(
            "ROUTEVIEWS_PEER_IP",
            "193.0.0.56",  # European IP range
        )

    def generate_table_dump(
        self,
        timestamp: int,
        prefix: str,
        as_path: list[int],
        next_hop: str,
        local_pref: int | None = None,
        med: int | None = None,
        atomic_aggregate: bool = False,
    ) -> dict[str, Any]:
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
        as_path: list[int],
        next_hop: str,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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
    ) -> dict[str, Any]:
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

    @staticmethod
    def to_telemetry_event(
        routeviews_message: dict[str, Any],
        scenario_name: str | None = None,
        attack_step: str | None = None,
    ) -> dict[str, Any]:
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


# Convenience functions with European defaults


def mock_routeviews_update(
    timestamp: int,
    prefix: str,
    as_path: list[int],
    next_hop: str,
    collector: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Generate a mock RouteViews UPDATE in telemetry format.

    Uses European defaults unless collector is specified.
    """
    # Use provided collector or default to Amsterdam
    actual_collector = collector or os.getenv(
        "ROUTEVIEWS_COLLECTOR", "route-views.amsix"
    )

    feed = RouteViewsFeedMock(collector=actual_collector)
    rv_msg = feed.generate_update(timestamp, prefix, as_path, next_hop, **kwargs)
    return RouteViewsFeedMock.to_telemetry_event(rv_msg)


def mock_routeviews_withdrawal(
    timestamp: int,
    prefix: str,
    collector: str | None = None,
) -> dict[str, Any]:
    """
    Generate a mock RouteViews WITHDRAWAL in telemetry format.

    Uses European defaults unless collector is specified.
    """
    # Use provided collector or default to Amsterdam
    actual_collector = collector or os.getenv(
        "ROUTEVIEWS_COLLECTOR", "route-views.amsix"
    )

    feed = RouteViewsFeedMock(collector=actual_collector)
    rv_msg = feed.generate_withdrawal(timestamp, prefix)
    return RouteViewsFeedMock.to_telemetry_event(rv_msg)


# European collector constants for easy reference
EUROPEAN_COLLECTORS = {
    "amsterdam": "route-views.amsix",
    "london": "route-views.linx",
    "frankfurt": "route-views.fra",  # If available
    "paris": "route-views.paris",  # If available
    "cape_town": "route-views.napafrica",  # Close to Europe
}


if __name__ == "__main__":
    # Example usage
    print("European RouteViews Feed Mock")
    print("=" * 50)

    # Show default European collector
    feed = RouteViewsFeedMock()
    print(f"Default collector: {feed.collector}")
    print(f"Default peer IP: {feed.peer_ip}")
    print()

    # Generate UPDATE
    update = feed.generate_update(
        timestamp=1767225600,
        prefix="203.0.113.0/24",
        as_path=[6939, 174, 64500],
        next_hop="198.32.176.1",
        attributes={"local_pref": 100, "med": 0},
    )

    print("RouteViews UPDATE (European format):")
    print(json.dumps(update, indent=2))

    # Convert to telemetry
    telemetry = RouteViewsFeedMock.to_telemetry_event(update, scenario_name="test")
    print("\nTelemetry format:")
    print(json.dumps(telemetry, indent=2))

    # Show available European collectors
    print("\nAvailable European collectors:")
    for location, collector in EUROPEAN_COLLECTORS.items():
        print(f"  {location.title():12} → {collector}")
